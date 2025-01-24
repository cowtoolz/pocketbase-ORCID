package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pocketbase/pocketbase/tools/types"
	"golang.org/x/oauth2"
)

func init() {
	Providers[NameORCID] = wrapFactory(NewORCIDProvider)
}

var _ Provider = (*ORCID)(nil)

// NameORCID is the unique name of the ORCID provider.
const NameORCID string = "ORCID"

// ORCID allows authentication via ORCID OAuth2.
type ORCID struct {
	BaseProvider
}

// NewORCIDProvider creates new ORCID provider instance with some defaults.
func NewORCIDProvider() *ORCID {
	return &ORCID{BaseProvider{
		ctx:         context.Background(),
		displayName: "ORCID",
		pkce:        true,
		scopes: []string{
			"/authenticate",
		},
		authURL:     "https://orcid.org/oauth/authorize",
		tokenURL:    "https://orcid.org/oauth/token",
		userInfoURL: "", // this is set later as it must be derived from the returned token
	}}
}

// FetchAuthUser returns an AuthUser instance based on the ORCID's user api.
//
// API reference: https://info.orcid.org/documentation/integration-guide/
func (p *ORCID) FetchAuthUser(token *oauth2.Token) (*AuthUser, error) {

	// deriving userInfoURL from the iD (i.e. username) returned in the token
	iD, ok := token.Extra("orcid").(string)
	if !ok || iD == "" {
		return nil, fmt.Errorf("Failed to get ORCID iD from OAuth2 token")
	}
	p.userInfoURL = `https://pub.orcid.org/v3.0/` + iD + `/person`

	// This is taken from the body of FetchRawUserInfo(),
	// we need to add "Accept" and "Content-type" header to get JSON, though
	req, err := http.NewRequestWithContext(p.ctx, "GET", p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-type", "application/json")
	data, err := p.sendRawUserInfoRequest(req, token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err := json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Name struct {
			GivenNames struct {
				Value string `json:"value"`
			} `json:"given-names"`
			FamilyName struct {
				Value string `json:"value"`
			} `json:"family-name"`
			CreditName struct {
				Value string `json:"value"`
			} `json:"credit-name"`
		} `json:"name"`
		Emails struct {
			Email []struct {
				Email string `json:"email"`
			} `json:"email"`
		} `json:"emails"`
	}{}
	if err := json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	name := extracted.Name.CreditName.Value
	if name == "" {
		// GivenNames is a required field on ORCID, so it will always be set
		name = extracted.Name.GivenNames.Value
		if extracted.Name.FamilyName.Value != "" {
			name += " " + extracted.Name.FamilyName.Value
		}
	}

	email := ""
	if len(extracted.Emails.Email) > 0 {
		email = extracted.Emails.Email[0].Email
	}

	user := &AuthUser{
		Name:         name,
		Username:     iD,
		Email:        email,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Id:           iD,
	}

	user.Expiry, _ = types.ParseDateTime(token.Expiry)

	return user, nil
}

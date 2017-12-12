package social

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/grafana/grafana/pkg/models"

	"golang.org/x/oauth2"
)

//Keycloak implementation
type Keycloak struct {
	*oauth2.Config
	allowedDomains       []string
	allowedOrganizations []string
	apiURL               string
	allowSignup          bool
	orgId                int64
}

//Type model
func (s *Keycloak) Type() int {
	return int(models.KEYCLOAK)
}

//IsEmailAllowed - Check if email is allowed
func (s *Keycloak) IsEmailAllowed(email string) bool {
	return isEmailAllowed(email, s.allowedDomains)
}

//IsSignupAllowed - Check if signup is allowed
func (s *Keycloak) IsSignupAllowed() bool {
	return s.allowSignup
}

//UserInfo - get user info
func (s *Keycloak) UserInfo(client *http.Client) (*BasicUserInfo, error) {
	var data struct {
		ID          int                 `json:"id"`
		Name        string              `json:"name"`
		DisplayName string              `json:"display_name"`
		Login       string              `json:"login"`
		Username    string              `json:"username"`
		Email       string              `json:"email"`
		Attributes  map[string][]string `json:"attributes"`
	}

	response, err := HttpGet(client, s.apiURL)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}

	err = json.Unmarshal(response.Body, &data)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}

	userInfo := &BasicUserInfo{
		Name:  data.Name,
		Login: data.Login,
		Email: data.Email,
		OrgId: s.orgId,
	}

	if userInfo.Name == "" && data.DisplayName != "" {
		userInfo.Name = data.DisplayName
	}

	if userInfo.Login == "" && data.Username != "" {
		userInfo.Login = data.Username
	}

	if userInfo.Login == "" {
		userInfo.Login = data.Email
	}

	return userInfo, nil
}

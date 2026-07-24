package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/rdurica/auth/internal/app"
	"github.com/rdurica/auth/internal/domain"
)

type UserAPI struct {
	svc      *app.AuthService
	problems ProblemWriter
}

func (u *UserAPI) GetProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := UserUUIDFromContext(r.Context())
	if !ok {
		u.problems.FromError(w, domain.ErrUnauthorized)
		return
	}
	profile, err := u.svc.GetProfile(r.Context(), id)
	if err != nil {
		u.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (u *UserAPI) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := UserUUIDFromContext(r.Context())
	if !ok {
		u.problems.FromError(w, domain.ErrUnauthorized)
		return
	}
	var raw map[string]json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		writeDecodeError(u.problems, w, err)
		return
	}
	in := app.UpdateProfileInput{}
	if v, exists := raw["firstName"]; exists {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			u.problems.Write(w, http.StatusBadRequest, "invalid_content", "invalid firstName", nil, nil)
			return
		}
		in.FirstName = &s
	}
	if v, exists := raw["lastName"]; exists {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			u.problems.Write(w, http.StatusBadRequest, "invalid_content", "invalid lastName", nil, nil)
			return
		}
		in.LastName = &s
	}
	if v, exists := raw["phone"]; exists {
		in.PhoneSet = true
		if string(v) == "null" {
			in.Phone = nil
		} else {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				u.problems.Write(w, http.StatusBadRequest, "invalid_content", "invalid phone", nil, nil)
				return
			}
			in.Phone = &s
		}
	}
	if err := u.svc.UpdateProfile(r.Context(), id, in); err != nil {
		u.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

func (u *UserAPI) ChangePassword(w http.ResponseWriter, r *http.Request) {
	id, ok := UserUUIDFromContext(r.Context())
	if !ok {
		u.problems.FromError(w, domain.ErrUnauthorized)
		return
	}
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(u.problems, w, err)
		return
	}
	if err := u.svc.ChangePassword(r.Context(), id, body.CurrentPassword, body.NewPassword); err != nil {
		u.problems.FromError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"passwordChanged": true})
}

func (u *UserAPI) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := UserUUIDFromContext(r.Context())
	if !ok {
		u.problems.FromError(w, domain.ErrUnauthorized)
		return
	}
	var body struct {
		Confirmation string `json:"confirmation"`
		Password     string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeError(u.problems, w, err)
		return
	}
	if err := u.svc.DeleteAccount(r.Context(), id, body.Confirmation, body.Password); err != nil {
		u.problems.FromError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

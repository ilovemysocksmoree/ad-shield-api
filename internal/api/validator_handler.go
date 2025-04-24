package api

import (
	"net/http"

	"github.com/bob17/adpis/internal/db"
)

func (a *APIServer) RBACValidatorHandler(w http.ResponseWriter, r *http.Request) {
	client, exist := r.Context().Value("client_info").(*db.ADClient)
	if !exist {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "client not found",
			"description": "clientID provided in bearer token is invalid",
			"status":      "failed",
		})

		return
	}

	user, exist := r.Context().Value("user_info").(*db.Users)
	if !exist {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "user not found",
			"description": "user provided in bearer token is invalid",
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "good to go",
		"description": "client and user is good, no fishy activity detected",
		"status":      "success",
		"docs": map[string]interface{}{
			"client": client,
			"user":   user,
		},
	})
}

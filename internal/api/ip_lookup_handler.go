package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bob17/adpis/internal/geo"
)

func (a *APIServer) handleIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method for IP-lookup, try method POST",
			"status":      "failed",
		})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid body",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	geoCfg := geo.NewGeoConfig(req.Domain)
	geoService := geo.NewGeoService(geoCfg)
	resp, err := geoService.Lookup()
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "lookup succeeded",
		"description": fmt.Sprintf("successfully lookuped for domain/ip: %s", req.Domain),
		"status":      "success",
		"docs":        resp,
	})
}

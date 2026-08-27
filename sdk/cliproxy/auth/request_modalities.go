package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

const imageInputModality = "image"

func sessionAffinityModalityKey(payload []byte) string {
	if requestRequiresImageInput(payload) {
		return "::modality=image"
	}
	return ""
}

func requestRequiresImageInput(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return false
	}
	return jsonValueRequiresImageInput(value)
}

func jsonValueRequiresImageInput(value any) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if jsonValueRequiresImageInput(item) {
				return true
			}
		}
	case map[string]any:
		if contentType, ok := typed["type"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(contentType)) {
			case "input_image", "image_url":
				return true
			}
		}
		if imageURL, ok := typed["image_url"]; ok && imageURL != nil {
			return true
		}
		for _, item := range typed {
			if jsonValueRequiresImageInput(item) {
				return true
			}
		}
	}
	return false
}

func authSupportsRequestModalities(registryRef *registry.ModelRegistry, auth *Auth, routeModel string, payload []byte) bool {
	if !requestRequiresImageInput(payload) || registryRef == nil || auth == nil {
		return true
	}
	modelKey := canonicalModelKey(routeModel)
	if modelKey == "" {
		return true
	}
	for _, model := range registryRef.GetModelsForClient(auth.ID) {
		if model == nil || !strings.EqualFold(canonicalModelKey(model.ID), modelKey) {
			continue
		}
		// An omitted capability list is treated as unknown for backwards compatibility.
		// An explicit list is authoritative and must contain image.
		if len(model.SupportedInputModalities) == 0 {
			return true
		}
		for _, modality := range model.SupportedInputModalities {
			if strings.EqualFold(strings.TrimSpace(modality), imageInputModality) {
				return true
			}
		}
		return false
	}
	return true
}

func filterAuthsForRequestModalities(registryRef *registry.ModelRegistry, auths []*Auth, routeModel string, payload []byte) ([]*Auth, error) {
	if !requestRequiresImageInput(payload) {
		return auths, nil
	}
	filtered := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if authSupportsRequestModalities(registryRef, auth, routeModel, payload) {
			filtered = append(filtered, auth)
		}
	}
	if len(filtered) == 0 && len(auths) > 0 {
		return nil, &Error{
			Code:       "unsupported_input_modality",
			Message:    "no available auth supports image input for the requested model",
			HTTPStatus: http.StatusBadRequest,
		}
	}
	return filtered, nil
}

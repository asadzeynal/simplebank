package api

import (
	"fmt"
	"github.com/asadzeynal/simplebank/token"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func addAuthorization(
	t *testing.T,
	r *http.Request,
	maker token.Maker,
	authorizationType string,
	username string,
	duration time.Duration,
) {
	token, err := maker.CreateToken(username, duration)
	require.NoError(t, err)

	authorizationHeader := fmt.Sprintf("%s %s", authorizationType, token)
	r.Header.Set(authorizationHeaderKey, authorizationHeader)
}

func TestAuthMiddleware(t *testing.T) {
	testCases := []struct {
		name          string
		setupAuth     func(t *testing.T, r *http.Request, maker token.Maker)
		checkResponse func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name: "OK",
			setupAuth: func(t *testing.T, r *http.Request, maker token.Maker) {
				addAuthorization(t, r, maker, authorizationTypeBearer, "user", time.Minute)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, recorder.Code, http.StatusOK)
			},
		},
		{
			name:      "NoAuth",
			setupAuth: func(t *testing.T, r *http.Request, maker token.Maker) {},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, recorder.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "UnsupportedAuth",
			setupAuth: func(t *testing.T, r *http.Request, maker token.Maker) {
				addAuthorization(t, r, maker, "unsupported", "user", time.Minute)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, recorder.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "InvalidAuthFormat",
			setupAuth: func(t *testing.T, r *http.Request, maker token.Maker) {
				addAuthorization(t, r, maker, "", "user", time.Minute)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, recorder.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "ExpiredToken",
			setupAuth: func(t *testing.T, r *http.Request, maker token.Maker) {
				addAuthorization(t, r, maker, authorizationTypeBearer, "user", -time.Minute)
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, recorder.Code, http.StatusUnauthorized)
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(t, nil)
			server.router.GET("/auth", authMiddleware(server.tokenMaker), func(context *gin.Context) {
				context.JSON(http.StatusOK, gin.H{})
			})
			recorder := httptest.NewRecorder()
			request, err := http.NewRequest(http.MethodGet, "/auth", nil)
			require.NoError(t, err)

			tc.setupAuth(t, request, server.tokenMaker)
			server.router.ServeHTTP(recorder, request)
			tc.checkResponse(t, recorder)
		})
	}
}

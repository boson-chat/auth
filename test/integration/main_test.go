package integration

import (
	"os"
	"testing"

	"github.com/boson-chat/auth/internal/logger"
)

func TestMain(m *testing.M) {
	logger.Logger(logger.WithServerName("auth-test"), logger.WithEnvironment("test"), logger.WithLevel("error"))
	os.Exit(m.Run())
}

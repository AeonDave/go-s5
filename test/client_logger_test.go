package socks5_test

import (
	"bytes"
	"log"
	"strings"
	"testing"

	client "github.com/AeonDave/go-s5/client"

	"github.com/stretchr/testify/require"
)

func TestClientLoggerDefaultLevel(t *testing.T) {
	var buf bytes.Buffer
	std := log.New(&buf, "", 0)

	logger := client.NewLogger(client.LoggerConfig{Base: std})
	logger.Debugf("debug %s", "ignored")
	require.Empty(t, buf.String(), "debug should be filtered at default level")

	logger.Errorf("error: %s", "visible")
	require.Contains(t, buf.String(), "error: visible")
}

func TestClientLoggerSilentLevel(t *testing.T) {
	var buf bytes.Buffer
	std := log.New(&buf, "", 0)

	logger := client.NewLogger(client.LoggerConfig{Base: std, Level: client.LogLevelOff, LevelSet: true})
	logger.Errorf("error")
	require.Empty(t, buf.String(), "level off should silence output")

	silent := client.NewSilentLogger()
	silent.Infof("info")
}

func TestClientLoggerInfoLevel(t *testing.T) {
	var buf bytes.Buffer
	std := log.New(&buf, "", 0)

	logger := client.NewStdLogger(std, client.LogLevelInfo)
	logger.Debugf("debug")
	require.Empty(t, buf.String(), "debug should not be printed at info level")

	logger.Infof("hello %s", "world")
	require.True(t, strings.Contains(buf.String(), "hello world"))
}

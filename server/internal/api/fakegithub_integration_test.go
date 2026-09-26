// SPDX-License-Identifier: Apache-2.0

//go:build integration

package api_test

const (
	testWebhookSecret = "api-test-webhook-secret-0123456789"
	fakePipeline      = "version: 1\njobs:\n  build:\n    image: alpine\n    steps: [{run: make}]\n"
)

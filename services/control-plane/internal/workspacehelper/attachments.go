package workspacehelper

import (
	"context"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/attachments"
)

func (h *Helper) stageAttachments(ctx context.Context, uploads []attachments.Upload) Response {
	if err := attachments.Validate(uploads); err != nil {
		return failure("invalid", "The attachment selection was invalid.")
	}
	stager, err := attachments.NewStager(h.attachmentRoot, nil, nil)
	if err != nil {
		return failure("internal", "Attachments could not be staged.")
	}
	staged, err := stager.Stage(ctx, uploads)
	if err != nil {
		return fromError(err)
	}
	return Response{Version: Version, OK: true, Attachments: staged}
}

func (h *Helper) cleanupAttachments(ctx context.Context) Response {
	stager, err := attachments.NewStager(h.attachmentRoot, nil, nil)
	if err != nil {
		return failure("internal", "Attachments could not be cleaned up.")
	}
	if err := stager.CleanupExpired(ctx); err != nil {
		return fromError(err)
	}
	return Response{Version: Version, OK: true}
}

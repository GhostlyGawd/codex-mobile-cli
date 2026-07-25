package application

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/attachments"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

func (a *Application) StageTerminalAttachments(
	ctx context.Context,
	principal httpapi.Principal,
	workspaceID, tabID string,
	request httpapi.StageAttachmentsRequest,
) (httpapi.StageAttachmentsResult, error) {
	// Resolve the tab through the owner-bound store before accepting any bytes
	// into the workspace runtime. A tab from another workspace or owner is not
	// a valid upload target.
	if _, err := a.deps.State.GetTerminalTab(ctx, principal.OwnerID, workspaceID, tabID); err != nil {
		return httpapi.StageAttachmentsResult{}, err
	}
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.StageAttachmentsResult{}, err
	}

	uploads := make([]attachments.Upload, 0, len(request.Attachments))
	expected := make([]attachmentExpectation, 0, len(request.Attachments))
	totalBytes := 0
	for _, item := range request.Attachments {
		uploads = append(uploads, attachments.Upload{MediaType: item.MediaType, Content: item.Content})
		expected = append(expected, attachmentExpectation{mediaType: item.MediaType, sizeBytes: len(item.Content)})
		totalBytes += len(item.Content)
	}
	if err := attachments.Validate(uploads); err != nil {
		return httpapi.StageAttachmentsResult{}, invalid(err)
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpAttachmentStage, Attachments: uploads,
	})
	if err != nil {
		a.audit(principal, workspaceID, "terminal_attachment.stage", "failed", "terminal_tab", tabID, map[string]any{
			"attachment_count": len(uploads), "total_bytes": totalBytes,
		})
		return httpapi.StageAttachmentsResult{}, err
	}
	if len(response.Attachments) != len(uploads) {
		return httpapi.StageAttachmentsResult{}, external(errors.New("workspace helper omitted staged attachments"))
	}
	result := httpapi.StageAttachmentsResult{Attachments: make([]httpapi.StagedAttachment, 0, len(response.Attachments))}
	for index, item := range response.Attachments {
		if !validStagedAttachment(item, expected[index], a.deps.Clock.Now()) {
			return httpapi.StageAttachmentsResult{}, external(errors.New("workspace helper returned invalid attachment metadata"))
		}
		result.Attachments = append(result.Attachments, httpapi.StagedAttachment{
			ID: item.ID, Path: item.Path, MediaType: item.MediaType,
			SizeBytes: item.SizeBytes, ExpiresAt: item.ExpiresAt,
		})
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.StageAttachmentsResult{}, err
	}
	a.audit(principal, workspaceID, "terminal_attachment.stage", "success", "terminal_tab", tabID, map[string]any{
		"attachment_count": len(uploads), "total_bytes": totalBytes,
	})
	return result, nil
}

type attachmentExpectation struct {
	mediaType string
	sizeBytes int
}

func validStagedAttachment(value attachments.Staged, expected attachmentExpectation, now time.Time) bool {
	if !strings.HasPrefix(value.ID, "att_") || len(value.ID) != 28 ||
		value.MediaType != expected.mediaType || value.SizeBytes != expected.sizeBytes ||
		!value.ExpiresAt.After(now.Add(-time.Minute)) || value.ExpiresAt.After(now.Add(attachments.StagingTTL+time.Minute)) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value.Path)))
	root := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(attachments.DefaultRoot)), "/") + "/"
	if clean != value.Path || !strings.HasPrefix(clean, root+"stage-") || strings.Contains(clean, "/../") {
		return false
	}
	base := filepath.Base(filepath.FromSlash(clean))
	return strings.HasPrefix(base, value.ID+".") && len(base) <= len(value.ID)+5
}

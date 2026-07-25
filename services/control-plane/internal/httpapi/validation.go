package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/mail"
	pathpkg "path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/attachments"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
)

const (
	maximumJSONRequestBytes = int64(1 << 20)
	maximumFileContentBytes = 8 << 20
	// JSON quotes, newlines, and backslashes can double the encoded size of a
	// valid text file. The decoded content remains capped at exactly 8 MiB.
	maximumFileRequestBytes       = int64(2*maximumFileContentBytes + 4096)
	maximumAttachmentRequestBytes = int64(12 << 20)
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	hexTokenPattern   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any, limit int64, required ...string) error {
	if err := requireJSONContentType(r); err != nil {
		return err
	}
	if r.ContentLength > limit {
		return payloadTooLarge()
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			return payloadTooLarge()
		}
		return invalidRequest()
	}
	defer func() {
		for index := range data {
			data[index] = 0
		}
	}()
	if len(bytes.TrimSpace(data)) == 0 || !utf8.Valid(data) {
		return invalidRequest()
	}
	fields, err := topLevelObjectFields(data)
	if err != nil {
		return invalidRequest()
	}
	for _, name := range required {
		value, present := fields[name]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalidRequest()
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalidRequest()
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return invalidRequest()
	}
	return nil
}

func topLevelObjectFields(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("JSON body must be an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		rawName, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := rawName.(string)
		if !ok {
			return nil, errors.New("invalid JSON object key")
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, errors.New("duplicate JSON object key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if err := rejectDuplicateJSONKeys(value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid JSON object end")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON value")
	}
	return fields, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing nested JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			rawName, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := rawName.(string)
			if !ok {
				return errors.New("invalid nested JSON object key")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate nested JSON object key")
			}
			seen[name] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid nested JSON object end")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid nested JSON array end")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func requireJSONContentType(r *http.Request) error {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return unsupportedMediaType()
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return unsupportedMediaType()
	}
	for key, value := range parameters {
		if !strings.EqualFold(key, "charset") || !strings.EqualFold(value, "utf-8") {
			return unsupportedMediaType()
		}
	}
	return nil
}

func requireEmptyBody(r *http.Request) error {
	if r.ContentLength > 0 {
		return invalidRequest()
	}
	if r.Body == nil {
		return nil
	}
	var one [1]byte
	n, err := r.Body.Read(one[:])
	if n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return invalidRequest()
	}
	return nil
}

func validateQuery(r *http.Request, allowed ...string) error {
	permitted := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		permitted[name] = struct{}{}
	}
	for name, values := range r.URL.Query() {
		if _, ok := permitted[name]; !ok || len(values) != 1 {
			return invalidRequest()
		}
	}
	return nil
}

func optionalQuery(r *http.Request, name string, maximum int) (*string, error) {
	if err := validateQuery(r, name); err != nil {
		return nil, err
	}
	values, present := r.URL.Query()[name]
	if !present {
		return nil, nil
	}
	if !validText(values[0], 0, maximum) {
		return nil, invalidRequest()
	}
	value := values[0]
	return &value, nil
}

func requiredQuery(r *http.Request, name string, maximum int) (string, error) {
	value, err := optionalQuery(r, name, maximum)
	if err != nil || value == nil || *value == "" {
		return "", invalidRequest()
	}
	return *value, nil
}

func validIdentifier(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && identifierPattern.MatchString(value)
}

func validRelativePath(value string) bool {
	if !validText(value, 1, 4096) || strings.Contains(value, `\`) || strings.ContainsRune(value, '\x00') ||
		strings.HasPrefix(value, "/") || value == "." || value == ".." || pathpkg.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func validBase64URL(value string) bool {
	if len(value) < 1 || len(value) > 1<<20 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func validCredentialID(value string) bool {
	if len(value) < 1 || len(value) > 1366 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 1 && len(decoded) <= 1024 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validAutonomy(value AutonomyMode) bool {
	return value == AutonomySafe || value == AutonomyBalanced || value == AutonomyFullAccess
}

func validRetention(value RetentionPolicy) bool {
	return value == RetentionSevenDays || value == RetentionThirtyDays || value == RetentionNinetyDays || value == RetentionKeepForever
}

func (value BootstrapRegistrationRequest) validate() error {
	if !validText(value.BootstrapToken, 32, 512) || !validDeviceIdentity(value.DeviceInstanceID, value.DeviceName) {
		return invalidRequest()
	}
	return nil
}

func (value DeviceIdentityRequest) validate() error {
	if !validDeviceIdentity(value.DeviceInstanceID, value.DeviceName) {
		return invalidRequest()
	}
	return nil
}

func (value PasskeyRegistrationCredential) validate() error {
	if !validIdentifier(value.CeremonyID) || !validBase64URL(value.CredentialID) || !validBase64URL(value.RawID) ||
		!validBase64URL(value.ClientDataJSON) || !validBase64URL(value.AttestationObject) ||
		!validDeviceIdentity(value.DeviceInstanceID, value.DeviceName) {
		return invalidRequest()
	}
	return nil
}

func (value PasskeyAssertionCredential) validate() error {
	if !validIdentifier(value.CeremonyID) || !validBase64URL(value.CredentialID) || !validBase64URL(value.RawID) ||
		!validBase64URL(value.ClientDataJSON) || !validBase64URL(value.AuthenticatorData) || !validBase64URL(value.Signature) ||
		(value.UserHandle != nil && !validBase64URL(*value.UserHandle)) ||
		!validDeviceIdentity(value.DeviceInstanceID, value.DeviceName) {
		return invalidRequest()
	}
	return nil
}

func validDeviceIdentity(instanceID, name string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(instanceID)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != instanceID ||
		!validText(name, 1, 120) || name != strings.TrimSpace(name) {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (value RefreshSessionRequest) validate() error {
	if !validText(value.RefreshToken, 32, 512) {
		return invalidRequest()
	}
	return nil
}

func (value CreateSecretRequest) validate() error {
	if !secretmodel.ValidName(value.Name) || (value.RepositoryID != nil && !validIdentifier(*value.RepositoryID)) ||
		secretmodel.ValidateValue(value.Value) != nil {
		return invalidRequest()
	}
	return nil
}

func (value UpdateSecretRequest) validate() error {
	if secretmodel.ValidateValue(value.Value) != nil {
		return invalidRequest()
	}
	return nil
}

func (value NewWorkspaceRequest) validate() error {
	if !validIdentifier(value.RepositoryID) || !validAutonomy(value.Autonomy) || !validRetention(value.Retention) ||
		(value.InitialPrompt != nil && !validText(*value.InitialPrompt, 0, 100000)) ||
		(value.BaseBranch != nil && !validText(*value.BaseBranch, 0, 255)) ||
		(value.TaskName != nil && !validText(*value.TaskName, 0, 200)) || len(value.EnvironmentVariables) > 100 ||
		(value.RequestedDiskGiB != nil && (*value.RequestedDiskGiB < int(core.MinimumWorkspaceDiskGiB) || *value.RequestedDiskGiB > int(core.MaximumWorkspaceDiskGiB))) {
		return invalidRequest()
	}
	for _, environmentValue := range value.EnvironmentVariables {
		if !validText(environmentValue, 0, 8192) {
			return invalidRequest()
		}
	}
	return nil
}

func (value WorkspaceActionRequest) validate() error {
	switch value.Action {
	case ActionStart, ActionSuspend, ActionResume, ActionStop, ActionRetryProvisioning, ActionDelete:
		if value.Retention != nil || value.IdleTimeoutMinutes != nil || value.Autonomy != nil {
			return invalidRequest()
		}
		return nil
	case ActionKeepAlive:
		if value.Retention != nil || value.IdleTimeoutMinutes != nil || value.Autonomy != nil {
			return invalidRequest()
		}
		return nil
	case ActionUpdatePolicy:
		if value.Retention == nil || value.IdleTimeoutMinutes == nil || !validRetention(*value.Retention) ||
			value.Autonomy != nil || (*value.IdleTimeoutMinutes != 0 && (*value.IdleTimeoutMinutes < 5 || *value.IdleTimeoutMinutes > 10080)) {
			return invalidRequest()
		}
		return nil
	case ActionUpdateAutonomy:
		if value.Autonomy == nil || !validAutonomy(*value.Autonomy) || value.Retention != nil || value.IdleTimeoutMinutes != nil {
			return invalidRequest()
		}
		return nil
	default:
		return invalidRequest()
	}
}

func (value ApprovalDecisionRequest) validate() error {
	if value.Decision != DecisionApprove && value.Decision != DecisionDeny {
		return invalidRequest()
	}
	return nil
}

func (value CreateTerminalTabRequest) validate() error {
	switch value.Kind {
	case TerminalCodex, TerminalShell, TerminalServer, TerminalTest, TerminalLog:
		return nil
	default:
		return invalidRequest()
	}
}

func (value RenameTerminalTabRequest) validate() error {
	if !validTerminalTitle(value.Title) {
		return invalidRequest()
	}
	return nil
}

func (value ReorderTerminalTabsRequest) validate() error {
	if len(value.TabIDs) < 1 || len(value.TabIDs) > 64 {
		return invalidRequest()
	}
	seen := make(map[string]struct{}, len(value.TabIDs))
	for _, tabID := range value.TabIDs {
		if !validIdentifier(tabID) {
			return invalidRequest()
		}
		if _, duplicate := seen[tabID]; duplicate {
			return invalidRequest()
		}
		seen[tabID] = struct{}{}
	}
	return nil
}

func (value CloseTerminalTabRequest) validate() error {
	if !value.Confirmed {
		return invalidRequest()
	}
	return nil
}

func (value ConfirmConnectionDisconnectRequest) validate() error {
	if !value.Confirmed {
		return invalidRequest()
	}
	return nil
}

func validTerminalTitle(value string) bool {
	value = strings.TrimSpace(value)
	if !validText(value, 1, 120) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' ||
			(character >= '\u202a' && character <= '\u202e') || (character >= '\u2066' && character <= '\u2069') {
			return false
		}
	}
	return true
}

func (value TerminalConnectRequest) validate() error {
	if value.AfterSequence > math.MaxInt64 || (value.ReconnectToken != nil && !validText(*value.ReconnectToken, 32, 512)) {
		return invalidRequest()
	}
	return nil
}

func (value StageAttachmentsRequest) validate() error {
	if len(value.Attachments) < 1 || len(value.Attachments) > attachments.MaximumCount {
		return invalidRequest()
	}
	uploads := make([]attachments.Upload, 0, len(value.Attachments))
	total := 0
	for _, item := range value.Attachments {
		if len(item.Content) < 1 {
			return invalidRequest()
		}
		if len(item.Content) > attachments.MaximumFileBytes {
			return payloadTooLarge()
		}
		total += len(item.Content)
		if total > attachments.MaximumTotalBytes {
			return payloadTooLarge()
		}
		uploads = append(uploads, attachments.Upload{MediaType: item.MediaType, Content: item.Content})
	}
	if err := attachments.Validate(uploads); err != nil {
		return invalidRequest()
	}
	return nil
}

func (value SaveFileRequest) validate() error {
	if len(value.Content) > maximumFileContentBytes {
		return payloadTooLarge()
	}
	if !utf8.ValidString(value.Content) || !validText(value.ExpectedETag, 1, 200) {
		return invalidRequest()
	}
	return nil
}

func (value StageRequest) validate() error {
	if !validRelativePath(value.Path) {
		return invalidRequest()
	}
	return nil
}

func (value CommitRequest) validate() error {
	if !validText(value.Message, 1, 10000) || !validText(value.AuthorName, 1, 200) || !validText(value.AuthorEmail, 1, 320) {
		return invalidRequest()
	}
	address, err := mail.ParseAddress(value.AuthorEmail)
	if err != nil || address.Address != value.AuthorEmail {
		return invalidRequest()
	}
	return nil
}

func (value PullRequestRequest) validate() error {
	if !validText(value.Title, 1, 256) || !validText(value.Body, 0, 65536) || !validText(value.BaseBranch, 1, 255) {
		return invalidRequest()
	}
	return nil
}

func (value GitDiscardRequest) validate() error {
	if !value.Confirmed || len(value.Paths) < 1 || len(value.Paths) > 500 {
		return invalidRequest()
	}
	seen := make(map[string]bool, len(value.Paths))
	for _, path := range value.Paths {
		if !validRelativePath(path) || seen[path] {
			return invalidRequest()
		}
		seen[path] = true
	}
	return nil
}

func (value CheckpointRestoreFileRequest) validate() error {
	if !value.Confirmed || !validRelativePath(value.Path) {
		return invalidRequest()
	}
	return nil
}

func (value CheckpointRestoreWorkspaceRequest) validate() error {
	if !value.Confirmed {
		return invalidRequest()
	}
	return nil
}

func (value PreviewAccessRequest) validate() error {
	if !validIdentifier(value.PreviewID) {
		return invalidRequest()
	}
	return nil
}

func (ScheduleMaintenanceRequest) validate() error { return nil }

func (value MaintenanceActionRequest) validate() error {
	switch value.Action {
	case "begin_update", "updates_applied", "begin_verification", "complete":
		return nil
	default:
		return invalidRequest()
	}
}

func (value UserSettings) validate() error {
	if !validAutonomy(value.AutonomyDefault) || !validRetention(value.RetentionDefault) ||
		value.IdleTimeoutMinutes < 5 || value.IdleTimeoutMinutes > 10080 ||
		math.IsNaN(value.TerminalFontSize) || math.IsInf(value.TerminalFontSize, 0) ||
		value.TerminalFontSize < 8 || value.TerminalFontSize > 48 || !validText(value.TerminalTheme, 0, 100) {
		return invalidRequest()
	}
	if value.TerminalCursorStyle != CursorBlock && value.TerminalCursorStyle != CursorBeam && value.TerminalCursorStyle != CursorUnderline {
		return invalidRequest()
	}
	return nil
}

func (value PushDeviceRegistration) validate() error {
	if len(value.Token) < 64 || len(value.Token) > 200 || !hexTokenPattern.MatchString(value.Token) ||
		(value.Environment != PushSandbox && value.Environment != PushProduction) || !validText(value.Locale, 2, 35) {
		return invalidRequest()
	}
	return nil
}

func invalidRequest() error {
	return &ProblemError{Status: http.StatusBadRequest, Code: "invalid_request", Title: "Invalid request", Detail: "The request did not match the API contract."}
}

func unsupportedMediaType() error {
	return &ProblemError{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Title: "Unsupported media type", Detail: "A JSON request body requires Content-Type application/json."}
}

func payloadTooLarge() error {
	return &ProblemError{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Title: "Payload too large", Detail: "The request body exceeded the endpoint limit."}
}

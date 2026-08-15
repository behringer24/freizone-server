package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Where attachment bytes live on this device.
//
// Kept apart from the account directory on purpose, and configurable
// (see [Options.MediaPath]). Everything else this package writes is small and
// structural -- keys, sessions, a few kilobytes of transcript -- and belongs
// wherever the account belongs. Pictures are neither: on a phone they plausibly
// belong in storage the system may clear, on a server they may belong on a
// different disk entirely, and a bot may want them nowhere at all. Defaulting
// them under the account directory is convenient; making that the only option
// would bake a phone's assumptions into a library three different things link
// against.
//
// The layout mirrors the transcript's, because the question asked of it is
// always the same one: what belongs to this message, in this chat.
//
//	<media>/<chat id>/<message id>          the file itself
//	<media>/<chat id>/<message id>.thumb    the inline preview
//
// A chat id is a peer account id for a one-to-one conversation and a group id
// for a group, exactly as in the transcript.

// mediaStore is the on-disk half of attachments.
type mediaStore struct{ root string }

// mediaPath returns where a message's attachment belongs. Both elements are
// checked, because a chat id and a message id both arrive from the network in
// some paths, and a peer that could name "../" would otherwise write outside
// the store.
func (m *mediaStore) mediaPath(chatID, messageID, suffix string) (string, error) {
	if err := safeElement(chatID); err != nil {
		return "", fmt.Errorf("client: chat id %q: %w", chatID, err)
	}
	if err := safeElement(messageID); err != nil {
		return "", fmt.Errorf("client: message id %q: %w", messageID, err)
	}
	return filepath.Join(m.root, chatID, messageID+suffix), nil
}

// WriteAttachmentFile stores the bytes for one message's attachment.
//
// Called on both sides and for the same reason each time: the sender writes
// its own copy *before* the message is even sent, which is what makes an
// unsent picture durable enough to retry after the app is closed; the receiver
// writes what it downloaded, so a picture is fetched once rather than on every
// scroll past it.
func (c *Client) WriteAttachmentFile(chatID, messageID string, data []byte) error {
	path, err := c.media.mediaPath(chatID, messageID, "")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("client: creating media directory: %w", err)
	}
	return writeFileAtomic(path, data)
}

// WriteAttachmentThumb stores the inline preview a message carried.
//
// Written the moment the message arrives, including on a background wake with
// no screen to draw on: it is a kilobyte, so it costs nothing, and it means a
// picture shows *something* immediately rather than an empty bubble that reads
// as a message with nothing in it.
func (c *Client) WriteAttachmentThumb(chatID, messageID string, thumb []byte) error {
	if len(thumb) == 0 {
		return nil
	}
	path, err := c.media.mediaPath(chatID, messageID, ".thumb")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("client: creating media directory: %w", err)
	}
	return writeFileAtomic(path, thumb)
}

// AttachmentFile returns the stored bytes for a message's attachment, or nil
// when there are none. A missing file is not an error: it is the normal state
// of a picture nobody has looked at yet.
func (c *Client) AttachmentFile(chatID, messageID string) ([]byte, error) {
	return c.readMedia(chatID, messageID, "")
}

// AttachmentThumb returns the stored preview, or nil when there is none.
func (c *Client) AttachmentThumb(chatID, messageID string) ([]byte, error) {
	return c.readMedia(chatID, messageID, ".thumb")
}

func (c *Client) readMedia(chatID, messageID, suffix string) ([]byte, error) {
	path, err := c.media.mediaPath(chatID, messageID, suffix)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("client: reading attachment: %w", err)
	}
	return data, nil
}

// EnsureAttachment returns an attachment's bytes, downloading them only if
// they are not already here.
//
// Idempotent on purpose: a screen asking again a moment later finds the file
// rather than starting a second download, which is what lets a caller fetch
// eagerly when a message arrives *and* lazily when a bubble is first drawn
// without the two fighting.
func (c *Client) EnsureAttachment(ctx context.Context, chatID, messageID, server string, att Attachment) ([]byte, error) {
	cached, err := c.AttachmentFile(chatID, messageID)
	if err != nil || cached != nil {
		return cached, err
	}
	data, err := c.DownloadAttachment(ctx, server, att)
	if err != nil {
		return nil, err
	}
	if err := c.WriteAttachmentFile(chatID, messageID, data); err != nil {
		return nil, err
	}

	// The plaintext is on disk and fsynced (writeFileAtomic syncs before the
	// rename), so the server copy has served its purpose: give up this
	// device's claim now instead of leaving it to occupy the recipient's quota
	// for the whole retention window. That is the contract docs/PROTOCOL.md
	// §10 states -- "the recipient is expected to DELETE the blob once it has
	// the plaintext safely on disk" -- with retention as the backstop for a
	// recipient that never comes back. With several recipients only this
	// device's claim goes; the file follows the last one.
	//
	// Its own context, not the caller's: that one arrives with whatever is
	// left of a download deadline, and a nearly-spent one would make the
	// release silently skip. Best effort either way -- nothing here may fail a
	// download whose bytes are already safe, and this package has no logger to
	// say so, which is precisely why the sweep exists.
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), blobReleaseTimeout)
	defer cancel()
	_ = c.DeleteBlob(releaseCtx, att.BlobID)

	return data, nil
}

// blobReleaseTimeout bounds the best-effort claim release above. Generous:
// missing it costs nothing but disk somebody's retention sweep will reclaim.
const blobReleaseTimeout = 15 * time.Second

// deleteMessageMedia removes one message's attachment bytes and its preview,
// [Client.DeleteMessage]'s half of what DeleteChatMedia does for a whole chat.
// Absence is the normal case rather than an error: most messages carry no
// picture, and a picture nobody looked at has a preview but no full file.
func (c *Client) deleteMessageMedia(chatID, messageID string) error {
	for _, suffix := range []string{"", ".thumb"} {
		path, err := c.media.mediaPath(chatID, messageID, suffix)
		if err != nil {
			return err
		}
		if err := removeFile(path); err != nil {
			return err
		}
	}
	return nil
}

// DeleteChatMedia removes everything stored for one chat. Called when a
// transcript is cleared or a conversation deleted: the messages are gone, and
// leaving their pictures behind means storage nobody can see or reach.
func (c *Client) DeleteChatMedia(chatID string) error {
	if err := safeElement(chatID); err != nil {
		return fmt.Errorf("client: chat id %q: %w", chatID, err)
	}
	if err := os.RemoveAll(filepath.Join(c.media.root, chatID)); err != nil {
		return fmt.Errorf("client: deleting chat media: %w", err)
	}
	return nil
}

// AttachmentPath and AttachmentThumbPath say where an attachment's bytes
// belong, whether or not anything is there yet.
//
// Exported because the bytes are better fetched than carried: a caller with a
// file reader -- an image widget, a share sheet -- wants a path, and moving
// megabytes through whatever boundary sits between it and this package would
// cost more than the download did. An empty string means the ids were unusable.
func (c *Client) AttachmentPath(chatID, messageID string) string {
	path, err := c.media.mediaPath(chatID, messageID, "")
	if err != nil {
		return ""
	}
	return path
}

// AttachmentThumbPath is [Client.AttachmentPath] for the inline preview, which
// is present from the moment the message arrived.
func (c *Client) AttachmentThumbPath(chatID, messageID string) string {
	path, err := c.media.mediaPath(chatID, messageID, ".thumb")
	if err != nil {
		return ""
	}
	return path
}

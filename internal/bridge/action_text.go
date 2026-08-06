package bridge

import (
	"context"
	"fmt"

	"github.com/chromedp/chromedp"
)

// concealedReply returns the safe response shape for an action that
// successfully wrote text. When req.Concealed is set, the plaintext is
// replaced with the literal string "[REDACTED]" and a length plus
// `concealed: true` flag is added so callers can confirm redaction was
// applied. When not concealed, the original echo behavior is preserved
// for debugging form fills.
//
// Use this everywhere a handler would otherwise return
// map[string]any{"<verb>": req.Text}.
func concealedReply(verb string, req ActionRequest, extras map[string]any) map[string]any {
	out := make(map[string]any, len(extras)+3)
	for k, v := range extras {
		out[k] = v
	}
	if req.Concealed {
		out[verb] = "[REDACTED]"
		out["len"] = len(req.Text)
		out["concealed"] = true
	} else {
		out[verb] = req.Text
	}
	return out
}

// safeReply is concealedReply plus automatic sensitivity detection (SMI-3579).
// Opt-in `concealed: true` keeps its historical shape. Otherwise the target
// element is probed: password / OTP / card-style fields get the redacted
// descriptor ({"<verb>_len": N, "redacted": true}); everything else keeps the
// plaintext echo. Probing fails closed — an unresolvable target is redacted.
func safeReply(ctx context.Context, verb string, selector string, nodeID int64, req ActionRequest, extras map[string]any) map[string]any {
	if req.Concealed {
		return concealedReply(verb, req, extras)
	}
	if fieldIsSensitive(ctx, selector, nodeID) {
		return redactedEcho(verb, req.Text, extras)
	}
	return concealedReply(verb, req, extras)
}

func (b *Bridge) actionType(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Text == "" {
		return nil, fmt.Errorf("text required for type")
	}
	if req.Selector != "" {
		// Probe before typing: the page may swap the node afterwards.
		echo := safeReply(ctx, "typed", req.Selector, 0, req, nil)
		if err := chromedp.Run(ctx,
			chromedp.Click(req.Selector, chromedp.ByQuery),
			chromedp.SendKeys(req.Selector, req.Text, chromedp.ByQuery),
		); err != nil {
			return nil, err
		}
		return echo, nil
	}
	if req.NodeID > 0 {
		echo := safeReply(ctx, "typed", "", req.NodeID, req, nil)
		if err := TypeByNodeID(ctx, req.NodeID, req.Text); err != nil {
			return nil, err
		}
		return echo, nil
	}
	return nil, fmt.Errorf("need selector or ref")
}

func (b *Bridge) actionFill(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Selector != "" {
		echo := safeReply(ctx, "filled", req.Selector, 0, req, nil)
		if err := chromedp.Run(ctx, chromedp.SetValue(req.Selector, req.Text, chromedp.ByQuery)); err != nil {
			return nil, err
		}
		return echo, nil
	}
	if req.NodeID > 0 {
		echo := safeReply(ctx, "filled", "", req.NodeID, req, nil)
		if err := FillByNodeID(ctx, req.NodeID, req.Text); err != nil {
			return nil, err
		}
		return echo, nil
	}
	return nil, fmt.Errorf("need selector or ref")
}

func (b *Bridge) actionPress(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Key == "" {
		return nil, fmt.Errorf("key required for press")
	}
	return map[string]any{"pressed": req.Key}, DispatchNamedKey(ctx, req.Key)
}

func (b *Bridge) actionHumanType(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Text == "" {
		return nil, fmt.Errorf("text required for humanType")
	}

	if req.Selector != "" {
		if err := chromedp.Run(ctx, chromedp.Focus(req.Selector, chromedp.ByQuery)); err != nil {
			return nil, err
		}
	} else if req.NodeID > 0 {
		// req.NodeID is a BackendNodeID from the accessibility tree (same as humanClick).
		// Must use DOM.focus with backendNodeId, not dom.Focus().WithNodeID() which
		// expects a DOM NodeID — a different ID space. Using the wrong type causes
		// "Could not find node with given id (-32000)". See issue #226.
		if err := focusBackendNode(ctx, req.NodeID); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("need selector, ref, or nodeId")
	}

	actions := Type(req.Text, req.Fast)
	if err := chromedp.Run(ctx, actions...); err != nil {
		return nil, err
	}

	// Focused above, so the focused element is the target.
	return safeReply(ctx, "typed", req.Selector, req.NodeID, req, map[string]any{"human": true}), nil
}

func (b *Bridge) actionKeyboardType(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Text == "" {
		return nil, fmt.Errorf("text required for keyboard-type")
	}
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		for _, ch := range req.Text {
			s := string(ch)
			params := map[string]any{
				"type":                  "keyDown",
				"text":                  s,
				"key":                   s,
				"unmodifiedText":        s,
				"windowsVirtualKeyCode": int(ch),
				"nativeVirtualKeyCode":  int(ch),
			}
			if err := chromedp.FromContext(ctx).Target.Execute(ctx, "Input.dispatchKeyEvent", params, nil); err != nil {
				return err
			}
			paramsUp := map[string]any{
				"type":                  "keyUp",
				"key":                   s,
				"windowsVirtualKeyCode": int(ch),
				"nativeVirtualKeyCode":  int(ch),
			}
			if err := chromedp.FromContext(ctx).Target.Execute(ctx, "Input.dispatchKeyEvent", paramsUp, nil); err != nil {
				return err
			}
		}
		return nil
	}))
	if err != nil {
		return nil, err
	}
	// Dispatches to whatever is focused, so probe the focused element.
	return safeReply(ctx, "typed", "", 0, req, nil), nil
}

func (b *Bridge) actionKeyboardInsert(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Text == "" {
		return nil, fmt.Errorf("text required for keyboard-inserttext")
	}
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		return chromedp.FromContext(ctx).Target.Execute(ctx, "Input.insertText", map[string]any{
			"text": req.Text,
		}, nil)
	}))
	if err != nil {
		return nil, err
	}
	return safeReply(ctx, "inserted", "", 0, req, nil), nil
}

func (b *Bridge) actionKeyDown(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Key == "" {
		return nil, fmt.Errorf("key required for keydown")
	}
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		params := map[string]any{"type": "keyDown", "key": req.Key}
		if def, ok := namedKeyDefs[req.Key]; ok {
			params["code"] = def.code
			params["windowsVirtualKeyCode"] = def.virtualKey
			params["nativeVirtualKeyCode"] = def.virtualKey
		}
		return chromedp.FromContext(ctx).Target.Execute(ctx, "Input.dispatchKeyEvent", params, nil)
	}))
	if err != nil {
		return nil, err
	}
	return map[string]any{"keydown": req.Key}, nil
}

func (b *Bridge) actionKeyUp(ctx context.Context, req ActionRequest) (map[string]any, error) {
	if req.Key == "" {
		return nil, fmt.Errorf("key required for keyup")
	}
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		params := map[string]any{"type": "keyUp", "key": req.Key}
		if def, ok := namedKeyDefs[req.Key]; ok {
			params["code"] = def.code
			params["windowsVirtualKeyCode"] = def.virtualKey
			params["nativeVirtualKeyCode"] = def.virtualKey
		}
		return chromedp.FromContext(ctx).Target.Execute(ctx, "Input.dispatchKeyEvent", params, nil)
	}))
	if err != nil {
		return nil, err
	}
	return map[string]any{"keyup": req.Key}, nil
}

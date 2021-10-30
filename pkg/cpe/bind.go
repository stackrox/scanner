///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
// Base revision: 2843d93852e5cfc5617c65acbd3c591f64f1d85c
///////////////////////////////////////////////////

package cpe

import "strings"

// BindFS returns the WFN bound as CPE 2.3 formatted string.
func (w WFN) BindFS() string {
	b := strings.Builder{}
	b.WriteString(`cpe:2.3`)
	for i := 0; i < NumAttr; i++ {
		b.WriteByte(':')
		w.Attr[i].bind(&b)
	}
	return b.String()
}

// Bind binds the value to a formatted string, writing it into the provided
// strings.Builder.
func (v *Value) bind(b *strings.Builder) (err error) {
	switch v.Kind {
	case ValueUnset, ValueAny:
		_, err = b.WriteRune('*')
	case ValueNA:
		_, err = b.WriteRune('-')
	case ValueSet:
		_, err = valueString.WriteString(b, v.V)
	}
	return err
}

// ValueString does FS character replacing.
var valueString = strings.NewReplacer(
	`\.`, `.`,
	`\-`, `-`,
	`\_`, `_`,
)

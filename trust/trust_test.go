package trust

import (
	"fmt"
	"testing"

	"github.com/fastcat/wirelink/fact"

	"github.com/stretchr/testify/assert"
)

func TestShouldAccept(t *testing.T) {
	type args struct {
		attr  fact.Attribute
		known bool
		level *Level
	}
	type test struct {
		name string
		args args
		want bool
	}

	create := func(name string, attr fact.Attribute, known bool, level Level, want bool) test {
		name = fmt.Sprintf("%s(%c,%v,%v)=%v", name, attr, known, level, want)
		return test{name, args{attr, known, &level}, want}
	}
	matrix := func(name string, attrs []fact.Attribute, known bool, levels []Level, want bool) []test {
		ret := make([]test, 0, len(attrs)*len(levels))
		for _, attr := range attrs {
			for _, level := range levels {
				ret = append(ret, create(name, attr, known, level, want))
			}
		}
		return ret
	}

	validAttrs := []fact.Attribute{
		fact.AttributeEndpointV4,
		fact.AttributeEndpointV6,
		fact.AttributeAllowedCidrV4,
		fact.AttributeAllowedCidrV6,
		fact.AttributeMember,
		fact.AttributeMemberMetadata,
	}
	invalidAttrs := []fact.Attribute{
		fact.AttributeUnknown,
		// alive doesn't go through trust
		fact.AttributeAlive,
		// signed group is a transport structure and never directly evaluated for trust
		fact.AttributeSignedGroup,
	}
	epAttrs := []fact.Attribute{
		fact.AttributeEndpointV4,
		fact.AttributeEndpointV6,
	}
	aipAttrs := []fact.Attribute{
		fact.AttributeAllowedCidrV4,
		fact.AttributeAllowedCidrV6,
	}
	memberAttr := []fact.Attribute{
		fact.AttributeMember,
		fact.AttributeMemberMetadata,
	}
	allLevels := []Level{Untrusted, Endpoint, AllowedIPs, Membership, DelegateTrust}

	tests := make([]test, 0, 10*max(len(validAttrs), len(invalidAttrs))*4) // estimate to shut up linter
	tests = append(tests, test{"nil trust", args{fact.AttributeAlive, true, nil}, false})
	tests = append(tests, matrix("gigo", invalidAttrs, false, allLevels, false)...)
	tests = append(tests, matrix("gigo", invalidAttrs, true, allLevels, false)...)
	tests = append(tests, matrix("new peer", validAttrs, false, []Level{Untrusted, Endpoint, AllowedIPs}, false)...)
	tests = append(tests, matrix("new peer", validAttrs, false, []Level{Membership, DelegateTrust}, true)...)
	tests = append(tests, matrix("ep", epAttrs, true, []Level{Untrusted}, false)...)
	tests = append(tests, matrix("ep", epAttrs, true, []Level{Endpoint, AllowedIPs, Membership, DelegateTrust}, true)...)
	tests = append(tests, matrix("aip", aipAttrs, true, []Level{Untrusted, Endpoint}, false)...)
	tests = append(tests, matrix("aip", aipAttrs, true, []Level{AllowedIPs, Membership, DelegateTrust}, true)...)
	tests = append(tests, matrix("member", memberAttr, true, []Level{Untrusted, Endpoint, AllowedIPs}, false)...)
	tests = append(tests, matrix("member", memberAttr, true, []Level{Membership, DelegateTrust}, true)...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldAccept(tt.args.attr, tt.args.known, tt.args.level)
			assert.Equal(t, tt.want, got)
		})
	}
}

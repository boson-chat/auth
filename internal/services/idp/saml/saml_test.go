package saml

import "testing"

const idpXML = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
</IDPSSODescriptor></EntityDescriptor>`

func TestNormalize(t *testing.T) {
	k := Kind{}
	out, err := k.Normalize(map[string]any{"idp_metadata_xml": idpXML, "name_id_format": "persistent", "attribute_map": map[string]any{"email": "mail"}})
	if err != nil {
		t.Fatal(err)
	}
	if out["name_id_format"] != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" || out["attribute_map"].(map[string]any)["email"] != "mail" {
		t.Fatalf("normalized: %v", out)
	}
	for _, bad := range []map[string]any{
		{},
		{"idp_metadata_url": "https://a/md", "idp_metadata_xml": idpXML},
		{"idp_metadata_url": "http://idp.example.com/md"},
		{"idp_metadata_xml": "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"x\"/>"},
		{"idp_metadata_xml": idpXML, "name_id_format": "transient"},
		{"idp_metadata_xml": idpXML, "unknown": true},
	} {
		if _, err := k.Normalize(bad); err == nil {
			t.Errorf("Normalize(%v) accepted", bad)
		}
	}
}

package ibm

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccIBMNetworkGatewayVlanAtachment_Basic(t *testing.T) {

	hostname := acctest.RandString(16)
	gatewayName := fmt.Sprintf("tfuatgw-%s", acctest.RandString(10))

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccCheckIBMNetworkGatewayVlanAttachmentBasic(gatewayName, hostname),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						"ibm_network_vlan.test_vlan", "bypass", "true"),
				),
			},
		},
	})
}

func testAccCheckIBMNetworkGatewayVlanAttachmentBasic(gatewayName, hostname string) string {
	return fmt.Sprintf(`
	resource "ibm_network_gateway" "terraform-acceptance-test-1" {
	       name   = "%s"
	       members {
				hostname               = "%s"
				domain                 = "terraformuat1.ibm.com"
				datacenter             = "ams01"
				network_speed          = 100
				private_network_only   = false
				tcp_monitoring         = true
				process_key_name       = "INTEL_SINGLE_XEON_1270_3_40_2"
				os_key_name            = "OS_VYATTA_5600_5_X_UP_TO_1GBPS_SUBSCRIPTION_EDITION_64_BIT"
				redundant_network      = false
				disk_key_names         = [ "HARD_DRIVE_2_00TB_SATA_II" ]
				public_bandwidth       = 20000
				memory                 = 4
				ipv6_enabled           = true
		   }
		  }
		  resource "ibm_network_gateway_vlan_attachment" "terraform-acceptance-test-2"{
			  gateway_id = "${ibm_network_gateway.terraform-acceptance-test-1.id}"
			  network_vlan_id = 645086
		  }
		  `, gatewayName, hostname)

}

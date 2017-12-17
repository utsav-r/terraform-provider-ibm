package ibm

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/softlayer/softlayer-go/datatypes"
	"github.com/softlayer/softlayer-go/filter"
	"github.com/softlayer/softlayer-go/helpers/location"
	"github.com/softlayer/softlayer-go/helpers/product"
	"github.com/softlayer/softlayer-go/services"
	"github.com/softlayer/softlayer-go/session"
	"github.com/softlayer/softlayer-go/sl"
)

const packageKeyName = "NETWORK_GATEWAY_APPLIANCE"

func resourceIBMNetworkGateway() *schema.Resource {
	return &schema.Resource{
		Create:   resourceIBMNetworkGatewayCreate,
		Read:     resourceIBMNetworkGatewayRead,
		Update:   resourceIBMNetworkGatewayUpdate,
		Delete:   resourceIBMNetworkGatewayDelete,
		Exists:   resourceIBMNetworkGatewayExists,
		Importer: &schema.ResourceImporter{},

		Schema: map[string]*schema.Schema{

			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the gateway",
			},

			"members": {
				Type:        schema.TypeSet,
				Description: "The hardware members of this network Gateway",
				Required:    true,
				MinItems:    1,
				MaxItems:    2,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"member_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"hostname": {
							Type:        schema.TypeString,
							Optional:    true,
							ForceNew:    true,
							DefaultFunc: genID,
							DiffSuppressFunc: func(k, o, n string, d *schema.ResourceData) bool {
								// FIXME: Work around another bug in terraform.
								// When a default function is used with an optional property,
								// terraform will always execute it on apply, even when the property
								// already has a value in the state for it. This causes a false diff.
								// Making the property Computed:true does not make a difference.
								if strings.HasPrefix(o, "terraformed-") && strings.HasPrefix(n, "terraformed-") {
									return true
								}
								return o == n
							},
						},

						"domain": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},

						"notes": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},

						"datacenter": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},

						"network_speed": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  100,
							ForceNew: true,
						},

						"tcp_monitoring": {
							Type:             schema.TypeBool,
							Optional:         true,
							Default:          false,
							ForceNew:         true,
							DiffSuppressFunc: applyOnce,
						},

						"process_key_name": {
							Type:             schema.TypeString,
							Optional:         true,
							ForceNew:         true,
							Default:          "INTEL_SINGLE_XEON_1270_3_40_2",
							DiffSuppressFunc: applyOnce,
						},

						"os_key_name": {
							Type:             schema.TypeString,
							Optional:         true,
							ForceNew:         true,
							Default:          "OS_VYATTA_5600_5_X_UP_TO_1GBPS_SUBSCRIPTION_EDITION_64_BIT",
							DiffSuppressFunc: applyOnce,
						},

						"redundant_network": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
							ForceNew: true,
						},
						"tags": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      schema.HashString,
						},
						"unbonded_network": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
							ForceNew: true,
						},

						"public_bandwidth": {
							Type:             schema.TypeInt,
							Optional:         true,
							ForceNew:         true,
							Default:          20000,
							DiffSuppressFunc: applyOnce,
						},

						"memory": {
							Type:     schema.TypeInt,
							Optional: true,
							ForceNew: true,
						},

						"storage_groups": {
							Type:     schema.TypeList,
							Optional: true,
							ForceNew: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"array_type_id": {
										Type:     schema.TypeInt,
										Required: true,
									},
									"hard_drives": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeInt},
										Required: true,
									},
									"array_size": {
										Type:     schema.TypeInt,
										Optional: true,
									},
									"partition_template_id": {
										Type:     schema.TypeInt,
										Optional: true,
									},
								},
							},
							DiffSuppressFunc: applyOnce,
						},
						"disk_key_names": {
							Type:             schema.TypeList,
							Optional:         true,
							ForceNew:         true,
							Elem:             &schema.Schema{Type: schema.TypeString},
							DiffSuppressFunc: applyOnce,
						},

						"public_vlan_id": {
							Type:     schema.TypeInt,
							Optional: true,
							ForceNew: true,
							Computed: true,
						},

						"private_vlan_id": {
							Type:     schema.TypeInt,
							Optional: true,
							ForceNew: true,
							Computed: true,
						},

						"public_ipv4_address": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"private_ipv4_address": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"ipv6_enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							ForceNew: true,
							Default:  true,
						},

						"ipv6_address": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"ipv6_address_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},

						"public_ipv6_subnet": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"vlan_number": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"private_network_only": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
							ForceNew: true,
						},
					},
				},
			},

			"associated_vlans": {
				Type:        schema.TypeSet,
				Description: "The VLAN instances associated with this Network Gateway",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"network_vlan_id": {
							Type:        schema.TypeInt,
							Description: "The Identifier of the VLAN to be associated",
							Optional:    true,
						},
						"bypass": {
							Type:        schema.TypeBool,
							Description: "Indicates if the VLAN should be in bypass or routed modes",
							Default:     true,
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

func hasBothMembersSameConfiguration(members []gatewayMember) bool {
	if len(members) != 2 {
		return false
	}
	m1 := members[0]
	m2 := members[1]
	for k, v := range m1 {
		if k == "hostname" || k == "domain" {
			continue
		}
		if !reflect.DeepEqual(v, m2[k]) {
			return false
		}
	}
	return true
}
func resourceIBMNetworkGatewayCreate(d *schema.ResourceData, meta interface{}) error {
	sess := meta.(ClientSession).SoftLayerSession()

	members := []gatewayMember{}
	for _, v := range d.Get("members").(*schema.Set).List() {
		m := v.(map[string]interface{})
		members = append(members, m)
	}

	// Build a montly Network gateway
	order, err := getMonthlyGatewayOrder(members[0], meta)
	if err != nil {
		return fmt.Errorf(
			"Encountered problem trying to get the Gateway order template: %s", err)
	}
	err = setHardwareOptions(members[0], &order.Hardware[0])
	if err != nil {
		return fmt.Errorf(
			"Encountered problem trying to configure Gateway options: %s", err)
	}

	equalConf := hasBothMembersSameConfiguration(members)

	if equalConf {
		//Ordering HA
		order.Quantity = sl.Int(2)
		order.Hardware = append(order.Hardware, datatypes.Hardware{
			Hostname: sl.String(members[1]["hostname"].(string)),
			Domain:   sl.String(members[1]["domain"].(string)),
		})
		err = setHardwareOptions(members[1], &order.Hardware[1])
		if err != nil {
			return fmt.Errorf(
				"Encountered problem trying to configure Gateway options: %s", err)
		}
	}

	var ProductOrder datatypes.Container_Product_Order
	ProductOrder.OrderContainers = make([]datatypes.Container_Product_Order, 1)
	ProductOrder.OrderContainers[0] = order

	_, err = services.GetProductOrderService(sess).VerifyOrder(&ProductOrder)
	if err != nil {
		return fmt.Errorf(
			"Encountered problem trying to verify the order: %s", err)
	}
	os.Exit(1)
	_, err = services.GetProductOrderService(sess).PlaceOrder(&ProductOrder, sl.Bool(false))
	if err != nil {
		return fmt.Errorf(
			"Encountered problem trying to place the order: %s", err)
	}

	bm, err := waitForNetworkGatewayMemberProvision(&order.Hardware[0], meta)
	if err != nil {
		return fmt.Errorf(
			"Error waiting for Gateway (%s) to become ready: %s", d.Id(), err)
	}

	id := *bm.(datatypes.Hardware).NetworkGatewayMember.NetworkGatewayId
	d.SetId(fmt.Sprintf("%d", id))
	log.Printf("[INFO] Gateway ID: %s", d.Id())

	member1Id := *bm.(datatypes.Hardware).Id
	members[0]["member_id"] = member1Id
	log.Printf("[INFO] Member 1 ID: %d", member1Id)

	err = setTagsAndNotes(members[0], meta)
	if err != nil {
		return err
	}

	if equalConf {
		bm, err := waitForNetworkGatewayMemberProvision(&order.Hardware[1], meta)
		if err != nil {
			return fmt.Errorf(
				"Error waiting for Gateway (%s) to become ready: %s", d.Id(), err)
		}
		member2Id := *bm.(datatypes.Hardware).Id
		log.Printf("[INFO] Member 2 ID: %d", member2Id)
		members[1]["member_id"] = member2Id
		err = setTagsAndNotes(members[1], meta)
		if err != nil {
			return err
		}

	}
	return resourceIBMNetworkGatewayUpdate(d, meta)
}

func resourceIBMNetworkGatewayRead(d *schema.ResourceData, meta interface{}) error {
	service := services.GetHardwareService(meta.(ClientSession).SoftLayerSession())

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Not a valid ID, must be an integer: %s", err)
	}

	result, err := service.Id(id).Mask(
		"hostname,domain," +
			"primaryIpAddress,primaryBackendIpAddress,privateNetworkOnlyFlag," +
			"notes,userData[value],tagReferences[id,tag[name]]," +
			"datacenter[id,name,longName]," +
			"primaryNetworkComponent[networkVlan[id,primaryRouter,vlanNumber],maxSpeed]," +
			"primaryBackendNetworkComponent[networkVlan[id,primaryRouter,vlanNumber],maxSpeed,redundancyEnabledFlag]," +
			"networkGatewayMember[networkGatewayId]," +
			"memoryCapacity,powerSupplyCount",
	).GetObject()

	if err != nil {
		return fmt.Errorf("Error retrieving Network Gateway: %s", err)
	}

	d.Set("hostname", *result.Hostname)
	d.Set("domain", *result.Domain)
	if result.NetworkGatewayMember != nil {
		d.Set("networkGatewayId", *result.NetworkGatewayMember.NetworkGatewayId)
	}

	if result.Datacenter != nil {
		d.Set("datacenter", *result.Datacenter.Name)
	}

	d.Set("network_speed", *result.PrimaryNetworkComponent.MaxSpeed)
	if result.PrimaryIpAddress != nil {
		d.Set("public_ipv4_address", *result.PrimaryIpAddress)
	}
	d.Set("private_ipv4_address", *result.PrimaryBackendIpAddress)

	d.Set("private_network_only", *result.PrivateNetworkOnlyFlag)

	if result.PrimaryNetworkComponent.NetworkVlan != nil {
		d.Set("public_vlan_id", *result.PrimaryNetworkComponent.NetworkVlan.Id)
	}

	if result.PrimaryBackendNetworkComponent.NetworkVlan != nil {
		d.Set("private_vlan_id", *result.PrimaryBackendNetworkComponent.NetworkVlan.Id)
	}

	d.Set("notes", sl.Get(result.Notes, nil))
	d.Set("memory", *result.MemoryCapacity)

	d.Set("redundant_network", false)
	d.Set("unbonded_network", false)

	backendNetworkComponent, err := service.Filter(
		filter.Build(
			filter.Path("backendNetworkComponents.status").Eq("ACTIVE"),
		),
	).Id(id).GetBackendNetworkComponents()

	if err != nil {
		return fmt.Errorf("Error retrieving Network Gateway network: %s", err)
	}

	if len(backendNetworkComponent) > 2 && result.PrimaryBackendNetworkComponent != nil {
		if *result.PrimaryBackendNetworkComponent.RedundancyEnabledFlag {
			d.Set("redundant_network", true)
		} else {
			d.Set("unbonded_network", true)
		}
	}

	tagReferences := result.TagReferences
	tagReferencesLen := len(tagReferences)
	if tagReferencesLen > 0 {
		tags := make([]string, 0, tagReferencesLen)
		for _, tagRef := range tagReferences {
			tags = append(tags, *tagRef.Tag.Name)
		}
		d.Set("tags", tags)
	}

	// connInfo := map[string]string{"type": "ssh"}
	// if !*result.PrivateNetworkOnlyFlag && result.PrimaryIpAddress != nil {
	// 	connInfo["host"] = *result.PrimaryIpAddress
	// } else {
	// 	connInfo["host"] = *result.PrimaryBackendIpAddress
	// }
	// d.SetConnInfo(connInfo)
	// where to set it
	d.Set("associated_vlans", resourceIBMNetworkGatewayVlanAssociatedReader(d, meta))

	return nil
}

func resourceIBMNetworkGatewayUpdate(d *schema.ResourceData, meta interface{}) error {
	id, _ := strconv.Atoi(d.Id())
	sess := meta.(ClientSession).SoftLayerSession()
	if d.HasChange("name") {
		service := services.GetNetworkGatewayService(sess)
		gwName := d.Get("name").(string)
		_, err := service.Id(id).EditObject(&datatypes.Network_Gateway{
			Name: sl.String(gwName),
		})
		if err != nil {
			return fmt.Errorf("Couldn't set the gateway name to %s", gwName)
		}
	}

	if d.HasChange("members") {
		o, n := d.GetChange("members")
		os := o.(*schema.Set)
		ns := n.(*schema.Set)

		add := ns.Difference(os).List()
		for _, v := range add {
			member := v.(gatewayMember)
			order, err := getMonthlyGatewayOrder(member, meta)
			if err != nil {
				return fmt.Errorf(
					"Encountered problem trying to get the Gateway order template: %s", err)
			}
			err = setHardwareOptions(member, &order.Hardware[0])
			if err != nil {
				return fmt.Errorf(
					"Encountered problem trying to configure Gateway options: %s", err)
			}
			order.ResourceGroupId = sl.Int(id)

			var ProductOrder datatypes.Container_Product_Order
			ProductOrder.OrderContainers = make([]datatypes.Container_Product_Order, 1)
			ProductOrder.OrderContainers[0] = order

			_, err = services.GetProductOrderService(sess).VerifyOrder(&ProductOrder)
			if err != nil {
				return fmt.Errorf(
					"Encountered problem trying to verify the order: %s", err)
			}
			//os.Exit(1)
			_, err = services.GetProductOrderService(sess).PlaceOrder(&ProductOrder, sl.Bool(false))
			if err != nil {
				return fmt.Errorf(
					"Encountered problem trying to place the order: %s", err)
			}

			bm, err := waitForNetworkGatewayMemberProvision(&order.Hardware[0], meta)
			if err != nil {
				return fmt.Errorf(
					"Error waiting for Gateway (%s) to become ready: %s", d.Id(), err)
			}
			id := *bm.(datatypes.Hardware).Id
			log.Printf("[INFO] Newly added member ID: %d", id)
			member["member_id"] = id
			err = setTagsAndNotes(member, meta)
			if err != nil {
				return err
			}

		}

		rem := os.Difference(ns).List()
		for _, v := range rem {
			member := v.(gatewayMember)
			log.Println("Removing member with ID", member.Id())
			err := deleteHardware(member, meta)
			if err != nil {
				return err
			}
		}
	}

	if d.HasChange("associated_vlans") {
		o, n := d.GetChange("associated_vlans")
		os := o.(*schema.Set)
		ns := n.(*schema.Set)
		add := expandVlans(ns.Difference(os).List(), id)
		if len(add) > 0 {
			err := resourceIBMNetworkGatewayVlanAssociate(d, meta, add, id)
			if err != nil {
				return err
			}
		}
		rem := expandVlans(os.Difference(ns).List(), id)
		if len(rem) > 0 {
			err := resourceIBMNetworkGatewayVlanDissociate(d, meta, rem, id)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func resourceIBMNetworkGatewayDelete(d *schema.ResourceData, meta interface{}) error {
	sess := meta.(ClientSession).SoftLayerSession()
	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return fmt.Errorf("Not a valid ID, must be an integer: %s", err)
	}
	service := services.GetNetworkGatewayService(sess)
	gw, err := service.Id(id).Mask("members[hardwareId]").GetObject()
	for _, v := range gw.Members {
		m := gatewayMember{
			"member_id": v.HardwareId,
		}
		err := deleteHardware(m, meta)
		if err != nil {
			return err
		}
	}
	//If both the hardwares have been deleted then gateway will go away as well
	d.SetId("")
	return nil
}

func resourceIBMNetworkGatewayExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	service := services.GetHardwareService(meta.(ClientSession).SoftLayerSession())

	id, err := strconv.Atoi(d.Id())
	if err != nil {
		return false, fmt.Errorf("Not a valid ID, must be an integer: %s", err)
	}

	result, err := service.Id(id).GetObject()
	if err != nil {
		if apiErr, ok := err.(sl.Error); !ok || apiErr.StatusCode != 404 {
			return false, fmt.Errorf("Error trying to retrieve Network Gateway: %s", err)
		}
	}

	return result.Id != nil && *result.Id == id, nil
}

func getMonthlyGatewayOrder(d dataRetriever, meta interface{}) (datatypes.Container_Product_Order, error) {
	sess := meta.(ClientSession).SoftLayerSession()

	// Validate attributes for network gateway ordering.
	model := packageKeyName

	datacenter, ok := d.GetOk("datacenter")
	if !ok {
		return datatypes.Container_Product_Order{}, fmt.Errorf("The attribute 'datacenter' is not defined.")
	}

	osKeyName := d.Get("os_key_name")

	process_key_name := d.Get("process_key_name")

	dc, err := location.GetDatacenterByName(sess, datacenter.(string), "id")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	// 1. Find a package id using Gateway package key name.
	pkg, err := getPackageByModelGateway(sess, model)

	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	if pkg.Id == nil {
		return datatypes.Container_Product_Order{}, err
	}

	// 2. Get all prices for the package
	items, err := product.GetPackageProducts(sess, *pkg.Id, productItemMaskWithPriceLocationGroupID)
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	// 3. Build price items
	server, err := getItemPriceId(items, "server", process_key_name.(string))
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	os, err := getItemPriceId(items, "os", osKeyName.(string))
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	ram, err := findMemoryItemPriceId(items, d)
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	portSpeed, err := findNetworkItemPriceId(items, d)
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	monitoring, err := getItemPriceId(items, "monitoring", "MONITORING_HOST_PING")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}
	if d.Get("tcp_monitoring").(bool) {
		monitoring, err = getItemPriceId(items, "monitoring", "MONITORING_HOST_PING_AND_TCP_SERVICE")
		if err != nil {
			return datatypes.Container_Product_Order{}, err
		}
	}
	// Other common default options
	priIpAddress, err := getItemPriceId(items, "pri_ip_addresses", "1_IP_ADDRESS")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	pri_ipv6_addresses, err := getItemPriceId(items, "pri_ipv6_addresses", "1_IPV6_ADDRESS")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	remoteManagement, err := getItemPriceId(items, "remote_management", "REBOOT_KVM_OVER_IP")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}
	vpnManagement, err := getItemPriceId(items, "vpn_management", "UNLIMITED_SSL_VPN_USERS_1_PPTP_VPN_USER_PER_ACCOUNT")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	notification, err := getItemPriceId(items, "notification", "NOTIFICATION_EMAIL_AND_TICKET")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}
	response, err := getItemPriceId(items, "response", "AUTOMATED_NOTIFICATION")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}
	vulnerabilityScanner, err := getItemPriceId(items, "vulnerability_scanner", "NESSUS_VULNERABILITY_ASSESSMENT_REPORTING")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	// Define an order object using basic paramters.

	order := datatypes.Container_Product_Order{
		ContainerIdentifier: sl.String(d.Get("hostname").(string)),
		Quantity:            sl.Int(2),
		Hardware: []datatypes.Hardware{
			{
				Hostname: sl.String(d.Get("hostname").(string)),
				Domain:   sl.String(d.Get("domain").(string)),
			},
		},
		Location:  sl.String(strconv.Itoa(*dc.Id)),
		PackageId: pkg.Id,
		Prices: []datatypes.Product_Item_Price{
			server,
			os,
			ram,
			portSpeed,
			priIpAddress,
			pri_ipv6_addresses,
			remoteManagement,
			vpnManagement,
			monitoring,
			notification,
			response,
			vulnerabilityScanner,
		},
	}

	// Add optional price ids.
	// Add public bandwidth

	publicBandwidth := d.Get("public_bandwidth")
	publicBandwidthStr := "BANDWIDTH_" + strconv.Itoa(publicBandwidth.(int)) + "_GB"
	bandwidth, err := getItemPriceId(items, "bandwidth", publicBandwidthStr)
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}
	order.Prices = append(order.Prices, bandwidth)

	// Add prices of disks.
	disks := d.Get("disk_key_names").([]interface{})
	diskLen := len(disks)
	if diskLen > 0 {
		for i, disk := range disks {
			diskPrice, err := getItemPriceId(items, "disk"+strconv.Itoa(i), disk.(string))
			if err != nil {
				return datatypes.Container_Product_Order{}, err
			}
			order.Prices = append(order.Prices, diskPrice)
		}
	}

	// Add storage_groups for RAID configuration
	diskController, err := getItemPriceId(items, "disk_controller", "DISK_CONTROLLER_NONRAID")
	if err != nil {
		return datatypes.Container_Product_Order{}, err
	}

	if _, ok := d.GetOk("storage_groups"); ok {
		order.StorageGroups = getStorageGroupsFromResourceData(d)
		diskController, err = getItemPriceId(items, "disk_controller", "DISK_CONTROLLER_RAID")
		if err != nil {
			return datatypes.Container_Product_Order{}, err
		}
	}
	order.Prices = append(order.Prices, diskController)

	return order, nil
}

func getPackageByModelGateway(sess *session.Session, model string) (datatypes.Product_Package, error) {
	objectMask := "id,keyName,name,description,isActive,type[keyName],categories[id,name,categoryCode]"
	service := services.GetProductPackageService(sess)
	availableModels := ""
	filterStr := "{\"items\": {\"categories\": {\"categoryCode\": {\"operation\":\"server\"}}},\"type\": {\"keyName\": {\"operation\":\"BARE_METAL_GATEWAY\"}}}"

	// Get package id
	packages, err := service.Mask(objectMask).
		Filter(filterStr).GetAllObjects()
	if err != nil {
		return datatypes.Product_Package{}, err
	}
	for _, pkg := range packages {
		availableModels = availableModels + *pkg.KeyName
		if pkg.Description != nil {
			availableModels = availableModels + " ( " + *pkg.Description + " ), "
		} else {
			availableModels = availableModels + ", "
		}
		if *pkg.KeyName == model {
			return pkg, nil
		}
	}
	return datatypes.Product_Package{}, fmt.Errorf("No Gateway package key name for %s. Available package key name(s) is(are) %s", model, availableModels)
}

func setHardwareOptions(m gatewayMember, hardware *datatypes.Hardware) error {
	public_vlan_id := m.Get("public_vlan_id").(int)

	if public_vlan_id > 0 {
		hardware.PrimaryNetworkComponent = &datatypes.Network_Component{
			NetworkVlan: &datatypes.Network_Vlan{Id: sl.Int(public_vlan_id)},
		}
	}

	private_vlan_id := m.Get("private_vlan_id").(int)
	if private_vlan_id > 0 {
		hardware.PrimaryBackendNetworkComponent = &datatypes.Network_Component{
			NetworkVlan: &datatypes.Network_Vlan{Id: sl.Int(private_vlan_id)},
		}
	}

	return nil
}

func waitForNoGatewayActiveTransactions(id int, meta interface{}) (interface{}, error) {
	log.Printf("Waiting for Gateway (%d) to have zero active transactions", id)
	service := services.GetHardwareServerService(meta.(ClientSession).SoftLayerSession())

	stateConf := &resource.StateChangeConf{
		Pending: []string{"retry", "active"},
		Target:  []string{"idle"},
		Refresh: func() (interface{}, string, error) {
			bm, err := service.Id(id).Mask("id,activeTransactionCount").GetObject()
			if err != nil {
				return false, "retry", nil
			}

			if bm.ActiveTransactionCount != nil && *bm.ActiveTransactionCount == 0 {
				return bm, "idle", nil
			}
			return bm, "active", nil

		},
		Timeout:        24 * time.Hour,
		Delay:          10 * time.Second,
		MinTimeout:     1 * time.Minute,
		NotFoundChecks: 24 * 60,
	}

	return stateConf.WaitForState()
}

// Network gateways or Bare metal creation does not return a  object with an Id.
// Have to wait on provision date to become available on server that matches
// hostname and domain.
// http://sldn.softlayer.com/blog/bpotter/ordering-bare-metal-servers-using-softlayer-api
func waitForNetworkGatewayMemberProvision(d *datatypes.Hardware, meta interface{}) (interface{}, error) {
	hostname := *d.Hostname
	domain := *d.Domain
	log.Printf("Waiting for Gateway (%s.%s) to be provisioned", hostname, domain)

	stateConf := &resource.StateChangeConf{
		Pending: []string{"retry", "pending"},
		Target:  []string{"provisioned"},
		Refresh: func() (interface{}, string, error) {
			service := services.GetAccountService(meta.(ClientSession).SoftLayerSession())
			bms, err := service.Filter(
				filter.Build(
					filter.Path("hardware.hostname").Eq(hostname),
					filter.Path("hardware.domain").Eq(domain),
				),
			).Mask("id,provisionDate,networkGatewayMember[networkGatewayId]").GetHardware()
			if err != nil {
				return false, "retry", nil
			}

			if len(bms) == 0 || bms[0].ProvisionDate == nil {
				return datatypes.Hardware{}, "pending", nil
			} else {
				return bms[0], "provisioned", nil
			}
		},
		Timeout:        24 * time.Hour,
		Delay:          10 * time.Second,
		MinTimeout:     1 * time.Minute,
		NotFoundChecks: 24 * 60,
	}

	return stateConf.WaitForState()
}

func expandVlans(configured []interface{}, id int) []datatypes.Network_Gateway_Vlan {
	vlans := make([]datatypes.Network_Gateway_Vlan, 0, len(configured))

	for _, lRaw := range configured {
		data := lRaw.(map[string]interface{})
		p := &datatypes.Network_Gateway_Vlan{}
		if v, ok := data["network_vlan_id"]; ok && v.(int) != 0 {
			p.NetworkVlanId = sl.Int(v.(int))
		}
		if v, ok := data["bypass"]; ok {
			p.BypassFlag = sl.Bool(v.(bool))
		}
		p.NetworkGatewayId = sl.Int(id)

		vlans = append(vlans, *p)
	}
	return vlans
}

func resourceIBMNetworkGatewayVlanAssociate(d *schema.ResourceData, meta interface{}, vlanObjects []datatypes.Network_Gateway_Vlan, id int) error {
	sess := meta.(ClientSession).SoftLayerSession()

	_, err := services.GetNetworkGatewayVlanService(sess).CreateObjects(vlanObjects)
	if err != nil {
		return fmt.Errorf(
			"Encountered problem trying to associate the VLAN'S : %s", err)
	}
	return nil
}

func resourceIBMNetworkGatewayVlanDissociate(d *schema.ResourceData, meta interface{}, vlanObjects []datatypes.Network_Gateway_Vlan, id int) error {
	sess := meta.(ClientSession).SoftLayerSession()
	_, err := services.GetNetworkGatewayVlanService(sess).DeleteObjects(vlanObjects)
	if err != nil {
		return fmt.Errorf(
			"Encountered problem trying to dissociate the VLAN'S : %s", err)
	}
	return nil
}

func resourceIBMNetworkGatewayVlanAssociatedReader(d *schema.ResourceData, meta interface{}) interface{} {
	sess := meta.(ClientSession).SoftLayerSession()
	networkGatewayID := d.Get("networkGatewayId").(int)
	allgateways, err := services.GetNetworkGatewayService(sess).GetInsideVlans()
	if err != nil {
		return fmt.Errorf(
			"Encountered problem trying to read the VLANs associated with  %d : %s", networkGatewayID, err)
	}

	return allgateways

}

func setTagsAndNotes(m gatewayMember, meta interface{}) error {
	err := setHardwareTags(m["member_id"].(int), m, meta)
	if err != nil {
		return err
	}

	if m["notes"].(string) != "" {
		err := setHardwareNotes(m["member_id"].(int), m, meta)
		if err != nil {
			return err
		}
	}
	return nil
}

//New types to resuse functions from other resources which does the same job
type dataRetriever interface {
	Get(string) interface{}
	GetOk(string) (interface{}, bool)
	Id() string
}
type gatewayMember map[string]interface{}

func (m gatewayMember) Get(k string) interface{} {
	if k == "restricted_network" {
		//findNetworkItemPriceId is used from bare metal and that looks for this key
		return false
	}
	return m[k]
}
func (m gatewayMember) GetOk(k string) (i interface{}, b bool) {
	i, b = m[k]
	return
}

func (m gatewayMember) Id() string {
	return strconv.Itoa(m["member_id"].(int))
}

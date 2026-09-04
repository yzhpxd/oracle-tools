package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

var (
	computeClient      core.ComputeClient
	networkClient      core.VirtualNetworkClient
	identityClient     identity.IdentityClient
	blockStorageClient core.BlockstorageClient // 用于查询硬盘容量
	config             common.ConfigurationProvider
	compartmentID      string
	reader             = bufio.NewReader(os.Stdin)

	// 👑 风控追踪变量
	lastFailTime    time.Time
	consecutiveFail int
)

// 辅助函数：安全读取输入
func readInput() string {
	str, _ := reader.ReadString('\n')
	return strings.TrimSpace(str)
}

// 辅助函数：解析多端口输入 (支持空格、中英文逗号混合)
func parsePortInput(input string) []int {
	input = strings.ReplaceAll(input, ",", " ")
	input = strings.ReplaceAll(input, "，", " ")

	var ports []int
	parts := strings.Fields(input)
	for _, p := range parts {
		port, err := strconv.Atoi(p)
		if err == nil && port >= 1 && port <= 65535 {
			ports = append(ports, port)
		} else {
			fmt.Printf("⚠️ 警告：已自动跳过无效输入 '%s'\n", p)
		}
	}
	return ports
}

func main() {
	fmt.Println("=========================================")
	fmt.Println("  Oracle Cloud 自动化管理工具 (Win/Go)  ")
	fmt.Println("=========================================")

	// 1. 代理选择
	fmt.Println("\n🌐 请选择网络连接模式:")
	fmt.Println("1) 直连 (Direct Connection) [默认]")
	fmt.Println("2) 代理 (Use Proxy, 如 Nekobox 走特定节点)")
	fmt.Print("请选择 [1/2]: ")

	netMode := readInput()
	if netMode == "2" {
		fmt.Print("请输入代理地址 (直接回车默认 http://127.0.0.1:2080): ")
		proxyAddr := readInput()
		if proxyAddr == "" {
			proxyAddr = "http://127.0.0.1:2080"
		}
		os.Setenv("HTTP_PROXY", proxyAddr)
		os.Setenv("HTTPS_PROXY", proxyAddr)
		fmt.Printf("✅ 已启用全局代理: %s\n", proxyAddr)
	} else {
		fmt.Println("✅ 采用系统直连模式")
	}

	// 2. 初始化 API 认证
	initAuth()

	// 3. 主菜单
	for {
		fmt.Println("\n====== 👑 主菜单 ======")
		fmt.Println("1) 实例管理 (开关机 / 重启 / 彻底删除 / 换IP / 自定义变配)")
		fmt.Println("2) 自动抢机 (定时调度 / 随机延迟 / 防封禁 / 自动IPv6)")
		fmt.Println("3) VCN 安全控制 (放行 IPv4/IPv6 端口 / 配置公网路由) 🛡️")
		fmt.Println("0) 退出")
		fmt.Print("请选择 [1/2/3/0]: ")

		switch readInput() {
		case "1":
			instanceManagerMenu()
		case "2":
			grabInstanceMenu()
		case "3":
			vcnSecurityMenu()
		case "0":
			fmt.Println("👋 退出程序...")
			os.Exit(0)
		default:
			fmt.Println("⚠️ 无效选择，请重新输入")
		}
	}
}

// ============ 初始化认证 ============
func initAuth() {
	configMap := make(map[string]string)
	fmt.Println("\n=== 🔑 API 凭证配置 ===")
	fmt.Println("请粘贴 API 配置文本 (包含 user=, fingerprint= 等)，完成后按【两下回车】确认：")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			configMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	tenancy := configMap["tenancy"]
	user := configMap["user"]
	region := configMap["region"]
	fingerprint := configMap["fingerprint"]

	if tenancy == "" || user == "" || region == "" || fingerprint == "" {
		log.Fatalf("❌ 解析失败：缺少必需的 API 参数。")
	}

	fmt.Print("\n📂 请将 key_file (.pem 文件) 拖入此窗口并回车: ")
	keyPath := strings.Trim(readInput(), `"'`)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("❌ 无法读取私钥文件: %v", err)
	}

	config = common.NewRawConfigurationProvider(tenancy, user, region, fingerprint, string(keyBytes), nil)

	computeClient, err = core.NewComputeClientWithConfigurationProvider(config)
	if err != nil {
		log.Fatalf("❌ 计算客户端初始化失败: %v", err)
	}

	// 更完善的 User-Agent 伪装
	userAgentPool := []string{
		"Terraform/1.0.11", "Terraform/1.1.7", "Terraform/1.2.9", "Terraform/1.3.0",
		"Oracle-CLI/3.20.0", "Oracle-CLI/3.22.1", "Oracle-CLI/3.23.0", "Oracle-CLI/3.24.0",
		"curl/7.64.1", "wget/1.20.3",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	computeClient.Interceptor = func(req *http.Request) error {
		req.Header.Set("User-Agent", userAgentPool[rand.Intn(len(userAgentPool))])
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		// 反爬虫头
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)))
		return nil
	}

	networkClient, err = core.NewVirtualNetworkClientWithConfigurationProvider(config)
	identityClient, err = identity.NewIdentityClientWithConfigurationProvider(config)
	blockStorageClient, err = core.NewBlockstorageClientWithConfigurationProvider(config)

	if err != nil {
		log.Fatalf("❌ 客户端初始化失败: %v", err)
	}

	compartmentID = tenancy
	fmt.Println("✅ 身份验证已就绪，配置及私钥加载成功 (已开启动态指纹伪装)！")
}

// ============ 获取引导卷(硬盘)大小 ============
func getBootVolumeSize(instanceID string, ad string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. 查找挂载到该实例的引导卷
	req := core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: common.String(ad), // 关键修复：API 强制要求必须带上可用区 AD
		CompartmentId:      common.String(compartmentID),
		InstanceId:         common.String(instanceID),
	}
	res, err := computeClient.ListBootVolumeAttachments(ctx, req)
	if err != nil || len(res.Items) == 0 {
		return 0
	}
	bootVolID := res.Items[0].BootVolumeId

	// 2. 查询该引导卷的详细大小
	bvReq := core.GetBootVolumeRequest{BootVolumeId: bootVolID}
	bvRes, err := blockStorageClient.GetBootVolume(ctx, bvReq)
	if err != nil || bvRes.BootVolume.SizeInGBs == nil {
		return 0
	}
	return *bvRes.BootVolume.SizeInGBs
}

// ============ IPv6 查询与 IP 获取 ============
func getInstanceIPs(instanceID string) (string, string) {
	req := core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(compartmentID),
		InstanceId:    common.String(instanceID),
	}
	res, err := computeClient.ListVnicAttachments(context.Background(), req)
	if err != nil || len(res.Items) == 0 {
		return "获取中/无网卡", "获取中/无网卡"
	}

	var ipv4List []string
	var ipv6List []string

	for _, attachment := range res.Items {
		vnicID := attachment.VnicId
		if vnicID == nil {
			continue
		}

		vnicReq := core.GetVnicRequest{VnicId: vnicID}
		vnicRes, err := networkClient.GetVnic(context.Background(), vnicReq)
		if err != nil {
			continue
		}

		if vnicRes.Vnic.PublicIp != nil && *vnicRes.Vnic.PublicIp != "" {
			ipv4List = append(ipv4List, *vnicRes.Vnic.PublicIp)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ipv6Res, err := networkClient.ListIpv6s(ctx, core.ListIpv6sRequest{
			VnicId: vnicID,
		})
		cancel()

		if err == nil && ipv6Res.Items != nil && len(ipv6Res.Items) > 0 {
			for _, ipItem := range ipv6Res.Items {
				if ipItem.IpAddress != nil && *ipItem.IpAddress != "" {
					ipv6List = append(ipv6List, *ipItem.IpAddress)
				}
			}
		}
	}

	ipv4 := "无公网IPv4"
	if len(ipv4List) > 0 {
		ipv4 = strings.Join(ipv4List, ", ")
	}

	ipv6 := "无IPv6"
	if len(ipv6List) > 0 {
		ipv6 = strings.Join(ipv6List, ", ")
	}

	return ipv4, ipv6
}

func getAllInstanceIPDetails(instanceID string) {
	fmt.Println("\n=== 📊 IP 地址详细信息 ===")
	req := core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(compartmentID),
		InstanceId:    common.String(instanceID),
	}
	res, err := computeClient.ListVnicAttachments(context.Background(), req)
	if err != nil {
		fmt.Printf("❌ 获取网卡列表失败: %v\n", err)
		return
	}

	for i, attachment := range res.Items {
		fmt.Printf("\n[网卡 %d]\n", i+1)
		if attachment.VnicId == nil {
			fmt.Println("  VNIC ID: 无")
			continue
		}
		fmt.Printf("  VNIC ID: %s\n", *attachment.VnicId)

		vnicReq := core.GetVnicRequest{VnicId: attachment.VnicId}
		vnicRes, err := networkClient.GetVnic(context.Background(), vnicReq)
		if err != nil {
			fmt.Printf("  ❌ 获取 VNIC 详情失败: %v\n", err)
			continue
		}

		if vnicRes.Vnic.PublicIp != nil {
			fmt.Printf("  公网 IPv4: %s\n", *vnicRes.Vnic.PublicIp)
		} else {
			fmt.Println("  公网 IPv4: 无")
		}

		if vnicRes.Vnic.PrivateIp != nil {
			fmt.Printf("  私有 IPv4: %s\n", *vnicRes.Vnic.PrivateIp)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ipv6Res, err := networkClient.ListIpv6s(ctx, core.ListIpv6sRequest{VnicId: attachment.VnicId})
		cancel()

		if err == nil && ipv6Res.Items != nil && len(ipv6Res.Items) > 0 {
			fmt.Println("  IPv6 地址:")
			for j, ipItem := range ipv6Res.Items {
				if ipItem.IpAddress != nil {
					fmt.Printf("    [%d] %s\n", j+1, *ipItem.IpAddress)
				}
			}
		} else {
			fmt.Println("  IPv6 地址: 无 (或查询超时)")
		}
	}
	fmt.Println()
}

// 核心功能：为实例检测并分配缺失的公网 IPv4 和 IPv6 地址
func assignIPv4AndIPv6(instanceID string) {
	fmt.Println("\n🚀 开始为实例检测并分配 IPv4 / IPv6 地址...")
	ctx := context.Background()

	// 1. 获取机器绑定的主网卡 (VNIC) 信息
	vnicReq := core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(compartmentID),
		InstanceId:    common.String(instanceID),
	}
	vnicRes, err := computeClient.ListVnicAttachments(ctx, vnicReq)
	if err != nil || len(vnicRes.Items) == 0 {
		fmt.Println("❌ 获取实例网卡失败，请确认实例是否正常运行。")
		return
	}
	vnicID := vnicRes.Items[0].VnicId

	// 2. 获取 VNIC 详情，拿到子网 ID 并检查当前 IPv4
	vnicDetailReq := core.GetVnicRequest{VnicId: vnicID}
	vnicDetailRes, err := networkClient.GetVnic(ctx, vnicDetailReq)
	if err != nil {
		fmt.Printf("❌ 获取 VNIC 详情失败: %v\n", err)
		return
	}
	subnetID := vnicDetailRes.Vnic.SubnetId

	// ---- 🟢 阶段一：分配公网 IPv4 ----
	if vnicDetailRes.Vnic.PublicIp != nil && *vnicDetailRes.Vnic.PublicIp != "" {
		fmt.Printf("✅ 实例已拥有公网 IPv4: %s，跳过分配。\n", *vnicDetailRes.Vnic.PublicIp)
	} else {
		fmt.Println("⏳ 检测到该网卡无公网 IPv4，正在尝试申请并绑定临时公网 IP...")
		privReq := core.ListPrivateIpsRequest{VnicId: vnicID}
		privRes, err := networkClient.ListPrivateIps(ctx, privReq)
		if err == nil && len(privRes.Items) > 0 {
			var primaryPrivIpID *string
			for _, p := range privRes.Items {
				if p.IsPrimary != nil && *p.IsPrimary {
					primaryPrivIpID = p.Id
					break
				}
			}
			if primaryPrivIpID == nil {
				primaryPrivIpID = privRes.Items[0].Id
			}

			createPubReq := core.CreatePublicIpRequest{
				CreatePublicIpDetails: core.CreatePublicIpDetails{
					Lifetime:      core.CreatePublicIpDetailsLifetimeEphemeral,
					CompartmentId: common.String(compartmentID),
					PrivateIpId:   primaryPrivIpID,
				},
			}
			createPubRes, err := networkClient.CreatePublicIp(ctx, createPubReq)
			if err != nil {
				fmt.Printf("❌ 公网 IPv4 分配失败: %v\n", err)
			} else if createPubRes.PublicIp.IpAddress != nil {
				fmt.Printf("🎉 公网 IPv4 分配成功: %s\n", *createPubRes.PublicIp.IpAddress)
			}
		}
	}

	// ---- 🟣 阶段二：分配 IPv6 ----
	subReq := core.GetSubnetRequest{SubnetId: subnetID}
	subRes, err := networkClient.GetSubnet(ctx, subReq)
	if err != nil || len(subRes.Subnet.Ipv6CidrBlocks) == 0 {
		fmt.Println("\n❌ 无法分配 IPv6：该实例所在的底层子网尚未开启 IPv6 支持。")
		fmt.Println("👉 解决方案：请先退回主菜单 -> 进入【3) VCN 安全控制】 -> 执行【5) 为 VCN 与子网开启 IPv6】，然后再回来重试！")
		return
	}

	ipv6Req := core.ListIpv6sRequest{VnicId: vnicID}
	ipv6Res, err := networkClient.ListIpv6s(ctx, ipv6Req)
	if err == nil && len(ipv6Res.Items) > 0 {
		fmt.Printf("✅ 实例已拥有 IPv6: %s，跳过分配。\n", *ipv6Res.Items[0].IpAddress)
		return
	}

	fmt.Println("⏳ 检测到该网卡无 IPv6 地址，正在向子网请求分配...")
	createIpv6Req := core.CreateIpv6Request{
		CreateIpv6Details: core.CreateIpv6Details{
			VnicId: vnicID,
		},
	}
	createIpv6Res, err := networkClient.CreateIpv6(ctx, createIpv6Req)
	if err != nil {
		fmt.Printf("❌ IPv6 分配失败: %v\n", err)
	} else if createIpv6Res.Ipv6.IpAddress != nil {
		fmt.Printf("🎉 IPv6 分配成功: %s\n", *createIpv6Res.Ipv6.IpAddress)
	}
}

// ============ 实例管理与换IP ============
func rotatePublicIP(instanceID string) (string, error) {
	vnicReq := core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(compartmentID),
		InstanceId:    common.String(instanceID),
	}
	vnicRes, err := computeClient.ListVnicAttachments(context.Background(), vnicReq)
	if err != nil || len(vnicRes.Items) == 0 {
		return "", fmt.Errorf("找不到绑定的网卡")
	}
	vnicID := vnicRes.Items[0].VnicId

	privReq := core.ListPrivateIpsRequest{VnicId: vnicID}
	privRes, err := networkClient.ListPrivateIps(context.Background(), privReq)
	if err != nil || len(privRes.Items) == 0 {
		return "", fmt.Errorf("无法获取私有 IP")
	}

	var primaryPrivIpID *string
	for _, p := range privRes.Items {
		if p.IsPrimary != nil && *p.IsPrimary {
			primaryPrivIpID = p.Id
			break
		}
	}
	if primaryPrivIpID == nil {
		primaryPrivIpID = privRes.Items[0].Id
	}

	pubReq := core.GetPublicIpByPrivateIpIdRequest{
		GetPublicIpByPrivateIpIdDetails: core.GetPublicIpByPrivateIpIdDetails{
			PrivateIpId: primaryPrivIpID,
		},
	}
	pubRes, err := networkClient.GetPublicIpByPrivateIpId(context.Background(), pubReq)
	if err == nil && pubRes.PublicIp.Id != nil {
		_, delErr := networkClient.DeletePublicIp(context.Background(), core.DeletePublicIpRequest{
			PublicIpId: pubRes.PublicIp.Id,
		})
		if delErr != nil {
			return "", fmt.Errorf("释放旧 IP 失败 (可能绑定了预留IP): %v", delErr)
		}
	}

	time.Sleep(3 * time.Second)

	createReq := core.CreatePublicIpRequest{
		CreatePublicIpDetails: core.CreatePublicIpDetails{
			Lifetime:      core.CreatePublicIpDetailsLifetimeEphemeral,
			CompartmentId: common.String(compartmentID),
			PrivateIpId:   primaryPrivIpID,
		},
	}
	createRes, err := networkClient.CreatePublicIp(context.Background(), createReq)
	if err != nil {
		return "", fmt.Errorf("申请新 IP 失败: %v", err)
	}

	if createRes.PublicIp.IpAddress != nil {
		return *createRes.PublicIp.IpAddress, nil
	}
	return "", fmt.Errorf("甲骨文未返回 IP 地址")
}

func instanceManagerMenu() {
	fmt.Println("\n⏳ 正在拉取当前区域的实例与 IP 列表，请稍候...")

	res, err := computeClient.ListInstances(context.Background(), core.ListInstancesRequest{
		CompartmentId: common.String(compartmentID),
	})

	var activeInstances []core.Instance

	if err != nil {
		fmt.Printf("❌ 获取列表失败: %v\n", err)
	} else {
		fmt.Println("\n=== 🖥️ 您的实例列表 ===")
		for _, inst := range res.Items {
			if inst.LifecycleState != core.InstanceLifecycleStateTerminated {
				activeInstances = append(activeInstances, inst)
			}
		}

		if len(activeInstances) == 0 {
			fmt.Println("⚠️ 当前区域没有运行中或已停止的实例。")
		} else {
			for i, inst := range activeInstances {
				ipv4, ipv6 := getInstanceIPs(*inst.Id)

				fmt.Printf("[%d] %s | 状态: %s | 规格: %s\n",
					i+1, *inst.DisplayName, inst.LifecycleState, *inst.Shape)
				fmt.Printf("    IPv4: %s\n    IPv6: %s\n    ID: ...%s\n", ipv4, ipv6, (*inst.Id)[len(*inst.Id)-15:])
			}
		}
	}

	fmt.Print("\n👉 请输入实例 [序号] 或直接粘贴 [完整 OCID] (输入 0 返回): ")
	input := readInput()
	if input == "0" || input == "" {
		return
	}

	var insID string
	var selectedInstance core.Instance
	var found bool

	if idx, err := strconv.Atoi(input); err == nil && idx > 0 && idx <= len(activeInstances) {
		selectedInstance = activeInstances[idx-1]
		insID = *selectedInstance.Id
		found = true
	} else {
		insID = input
		if !strings.HasPrefix(insID, "ocid1.instance.") {
			fmt.Println("❌ 无效输入，OCID 格式错误或序号超出范围。")
			return
		}
		// 如果用户手动粘贴了 OCID，去云端单独查询这台机器的详情
		req := core.GetInstanceRequest{InstanceId: common.String(insID)}
		res, err := computeClient.GetInstance(context.Background(), req)
		if err == nil {
			selectedInstance = res.Instance
			found = true
		}
	}

	// 打印详细信息
	if found {
		fmt.Printf("\n✅ 已选中实例: %s\n", *selectedInstance.DisplayName)

		var cpu, ram float32
		if selectedInstance.ShapeConfig != nil {
			if selectedInstance.ShapeConfig.Ocpus != nil {
				cpu = *selectedInstance.ShapeConfig.Ocpus
			}
			if selectedInstance.ShapeConfig.MemoryInGBs != nil {
				ram = *selectedInstance.ShapeConfig.MemoryInGBs
			}
		}
		fmt.Printf("🖥️  当前规格: %s\n", *selectedInstance.Shape)
		fmt.Printf("⚙️  配置参数: %v 核 CPU | %v GB 内存\n", cpu, ram)

		// 获取并打印 IP 地址
		ipv4, ipv6 := getInstanceIPs(insID)
		fmt.Printf("🌐 公网 IPv4: %s\n", ipv4)
		fmt.Printf("🌍 公网 IPv6: %s\n", ipv6)

		fmt.Print("⏳ 正在获取硬盘信息...")

		// 提取当前实例所在的可用区 (AD)，传给查询硬盘的函数
		var adName string
		if selectedInstance.AvailabilityDomain != nil {
			adName = *selectedInstance.AvailabilityDomain
		}
		diskSize := getBootVolumeSize(insID, adName)

		if diskSize > 0 {
			fmt.Printf("\r💾 硬盘容量: %d GB            \n", diskSize) // \r 会自动覆盖前方的“正在获取”提示
		} else {
			fmt.Printf("\r💾 硬盘容量: 获取失败 (可能是 API 权限不足)\n")
		}
	} else {
		fmt.Println("\n✅ 已选中目标 OCID (未能获取到详细配置信息)")
	}

	fmt.Println("\n--- ⚙️ 实例控制中心 ---")
	fmt.Println("1) 正常重启 (SOFTRESET)  2) 强制重启 (HARDRESET)")
	fmt.Println("3) 启动实例 (START)      4) 停止实例 (STOP)")
	fmt.Println("5) 彻底删除 (TERMINATE)  6) 🔄 自动换 IP (盲刷到通为止)")
	fmt.Println("7) 🚀 自定义变配 (手动输入核心与内存 / 缺货自动重试)")
	fmt.Println("8) 📊 查看详细 IP 信息")
	fmt.Println("9) 🌐 一键为实例分配公网 IPv4 与 IPv6 地址")
	fmt.Println("10) 🔄 救砖重装: Win11 彻底重装回原版 Ubuntu 20.04 (规避200G限额)")
	fmt.Println("11) 💾 扩容硬盘 (仅支持增大，最高上限总和 200G)")
	fmt.Println("12) 📸 创建系统备份 (Ghost 快照，免费最多保留 5 个)")
	fmt.Println("13) ⏪ 从备份恢复系统 (自动删机重建，规避配额超限)")
	fmt.Print("请选择操作: ")

	switch readInput() {
	case "1":
		doInstanceAction(insID, "SOFTRESET")
	case "2":
		doInstanceAction(insID, "HARDRESET")
	case "3":
		doInstanceAction(insID, "START")
	case "4":
		doInstanceAction(insID, "STOP")
	case "5":
		fmt.Print("⚠️ 确定彻底删除吗？(y/n): ")
		if readInput() == "y" {
			computeClient.TerminateInstance(context.Background(), core.TerminateInstanceRequest{InstanceId: common.String(insID)})
			fmt.Println("🗑️ 正在发送删除指令...")
		}
	case "6":
		autoRotateIPUntilReachable(insID)
	case "7":
		fmt.Println("\n--- 🎛️ 实例自定义变配 ---")
		fmt.Print("👉 请输入目标 OCPU 核心数 (例如 1, 2, 3, 4): ")
		coresInput := readInput()
		cores, err1 := strconv.ParseFloat(coresInput, 32)

		fmt.Print("👉 请输入目标内存大小(GB) (例如 6, 12, 18, 24): ")
		ramInput := readInput()
		ram, err2 := strconv.ParseFloat(ramInput, 32)

		if err1 != nil || err2 != nil || cores <= 0 || ram <= 0 {
			fmt.Println("⚠️ 数值输入无效，操作取消。")
		} else {
			autoChangeShape(insID, float32(cores), float32(ram))
		}
	case "8":
		getAllInstanceIPDetails(insID)
	case "9":
		assignIPv4AndIPv6(insID)
	case "10":
		rebuildToUbuntu2004(selectedInstance)
	case "11":
		resizeBootVolume(selectedInstance)
	case "12":
		createBootVolumeBackup(selectedInstance)
	case "13":
		restoreFromBackup(selectedInstance)
	default:
		fmt.Println("⚠️ 无效操作")
	}
}

func doInstanceAction(id, action string) {
	fmt.Printf("🔄 发送 [%s] 指令...\n", action)
	_, err := computeClient.InstanceAction(context.Background(), core.InstanceActionRequest{
		InstanceId: common.String(id),
		Action:     core.InstanceActionActionEnum(action),
	})
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
	} else {
		fmt.Println("✅ 成功")
	}
}

func autoRotateIPUntilReachable(instanceID string) {
	fmt.Println("🚀 启动自动换 IP (SSH 通车检测)...")
	fmt.Println("⚠️ 警告：请确保此实例未绑定您珍贵的【预留 IP】，否则会被直接删除！")
	for {
		fmt.Printf("\n[%s] 正在请求更换公共 IP...\n", time.Now().Format("15:04:05"))

		newIP, err := rotatePublicIP(instanceID)

		if err != nil {
			fmt.Printf("❌ 更换失败: %v，10秒后重试...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}

		fmt.Printf("🔄 已成功分配新 IP: %s\n", newIP)
		fmt.Println("⏳ 等待 10 秒钟让甲骨文路由生效...")
		time.Sleep(10 * time.Second)

		fmt.Printf("🕵️ 正在测试 %s:22 端口连通性...\n", newIP)
		conn, err := net.DialTimeout("tcp", newIP+":22", 3*time.Second)
		if err == nil {
			conn.Close()
			fmt.Printf("✅ 通车！新 IP %s 完全可用，换 IP 任务结束。\n", newIP)
			break
		}

		fmt.Println("🚫 不通 (可能被墙或未开机)，准备再次更换...")
	}
}

// ============ API 自动发现资源 ============
func selectAvailabilityDomain() string {
	fmt.Println("\n⏳ 正在拉取可用区 (AD) 信息...")
	res, err := identityClient.ListAvailabilityDomains(context.Background(), identity.ListAvailabilityDomainsRequest{
		CompartmentId: common.String(compartmentID),
	})

	if err != nil || len(res.Items) == 0 {
		fmt.Print("❌ 无法自动获取，请手动粘贴 AD 名称: ")
		return readInput()
	}

	if len(res.Items) == 1 {
		adName := *res.Items[0].Name
		fmt.Printf("✅ 区域仅有 1 个可用区，已自动加载: %s\n", adName)
		return adName
	}

	fmt.Println("=== 🏢 可用区列表 ===")
	for i, ad := range res.Items {
		fmt.Printf("[%d] %s\n", i+1, *ad.Name)
	}
	fmt.Print("👉 请选择可用区 [序号]: ")
	input := readInput()
	if idx, err := strconv.Atoi(input); err == nil && idx > 0 && idx <= len(res.Items) {
		fmt.Printf("✅ 已选中: %s\n", *res.Items[idx-1].Name)
		return *res.Items[idx-1].Name
	}
	return *res.Items[0].Name
}

// 核心功能：一键初始化基础网络环境 (VCN + IGW + 路由 + 子网)
func autoCreateNetwork() string {
	fmt.Println("\n=== 🏗️ 开始荒野拓荒：初始化基础网络环境 ===")
	fmt.Println("⏳ 1/4 正在为您创建全新的 VCN (网段 10.0.0.0/16)...")

	ctx := context.Background()

	// 1. 创建 VCN
	vcnReq := core.CreateVcnRequest{
		CreateVcnDetails: core.CreateVcnDetails{
			CompartmentId: common.String(compartmentID),
			DisplayName:   common.String("Oraman-Auto-VCN"),
			CidrBlock:     common.String("10.0.0.0/16"),
		},
	}
	vcnRes, err := networkClient.CreateVcn(ctx, vcnReq)
	if err != nil {
		fmt.Printf("❌ 创建 VCN 失败: %v\n", err)
		return ""
	}
	vcnID := vcnRes.Vcn.Id
	defaultRtID := vcnRes.Vcn.DefaultRouteTableId
	fmt.Printf("✅ VCN 创建成功! ID: ...%s\n", (*vcnID)[len(*vcnID)-15:])

	// 2. 创建 Internet Gateway (IGW)
	fmt.Println("⏳ 2/4 正在创建并绑定互联网网关 (IGW)...")
	igwReq := core.CreateInternetGatewayRequest{
		CreateInternetGatewayDetails: core.CreateInternetGatewayDetails{
			CompartmentId: common.String(compartmentID),
			DisplayName:   common.String("Oraman-Auto-IGW"),
			IsEnabled:     common.Bool(true),
			VcnId:         vcnID,
		},
	}
	igwRes, err := networkClient.CreateInternetGateway(ctx, igwReq)
	if err != nil {
		fmt.Printf("❌ 创建 IGW 失败: %v\n", err)
		return ""
	}
	igwID := igwRes.InternetGateway.Id
	fmt.Println("✅ 互联网网关创建成功!")

	// 3. 配置默认路由表
	fmt.Println("⏳ 3/4 正在配置默认路由表 (将 0.0.0.0/0 指向 IGW)...")
	rtReq := core.UpdateRouteTableRequest{
		RtId: defaultRtID,
		UpdateRouteTableDetails: core.UpdateRouteTableDetails{
			RouteRules: []core.RouteRule{
				{
					NetworkEntityId: igwID,
					Destination:     common.String("0.0.0.0/0"),
					DestinationType: core.RouteRuleDestinationTypeCidrBlock,
				},
			},
		},
	}
	_, err = networkClient.UpdateRouteTable(ctx, rtReq)
	if err != nil {
		fmt.Printf("❌ 路由表更新失败: %v\n", err)
	} else {
		fmt.Println("✅ 路由表配置成功，公网已打通!")
	}

	// 4. 创建子网
	fmt.Println("⏳ 4/4 正在划分默认子网 (网段 10.0.0.0/24)...")
	subnetReq := core.CreateSubnetRequest{
		CreateSubnetDetails: core.CreateSubnetDetails{
			CompartmentId: common.String(compartmentID),
			DisplayName:   common.String("Oraman-Auto-Subnet"),
			VcnId:         vcnID,
			CidrBlock:     common.String("10.0.0.0/24"),
			RouteTableId:  defaultRtID,
		},
	}

	time.Sleep(2 * time.Second)

	subnetRes, err := networkClient.CreateSubnet(ctx, subnetReq)
	if err != nil {
		fmt.Printf("❌ 创建子网失败: %v\n", err)
		return ""
	}

	newSubnetID := *subnetRes.Subnet.Id
	fmt.Printf("🎉 基础网络初始化大功告成！子网已就绪。\n👉 新子网 OCID: %s\n", newSubnetID)
	return newSubnetID
}

func selectSubnet() string {
	fmt.Println("\n⏳ 正在拉取虚拟云网络 (VCN) 子网列表...")
	res, err := networkClient.ListSubnets(context.Background(), core.ListSubnetsRequest{
		CompartmentId: common.String(compartmentID),
	})

	if err != nil || len(res.Items) == 0 {
		fmt.Println("⚠️ 当前区域没有任何子网 (疑似全新区域，无网络环境)。")
		fmt.Print("👉 是否一键自动创建基础网络 (VCN + IGW + 路由 + 子网)？(y/n): ")
		if readInput() == "y" {
			newID := autoCreateNetwork()
			if newID != "" {
				return newID
			}
		}

		fmt.Print("❌ 自动建网已跳过或失败，请手动粘贴 Subnet OCID (或输入 0 退出): ")
		return readInput()
	}

	fmt.Println("=== 🌐 可用子网列表 ===")
	for i, subnet := range res.Items {
		fmt.Printf("[%d] %s | CIDR: %s\n", i+1, *subnet.DisplayName, *subnet.CidrBlock)
	}

	fmt.Print("👉 请输入子网 [序号] 或直接粘贴 [完整 OCID]: ")
	input := readInput()

	if idx, err := strconv.Atoi(input); err == nil && idx > 0 && idx <= len(res.Items) {
		fmt.Printf("✅ 已自动选中子网: %s\n", *res.Items[idx-1].DisplayName)
		return *res.Items[idx-1].Id
	}
	return input
}

func selectImage(cpuShape string) string {
	fmt.Println("\n=== 💿 操作系统镜像选择 ===")
	fmt.Println("1) Ubuntu 22.04 (自动拉取当前区域最新版)")
	fmt.Println("2) Oracle Linux 8 (官方默认系统)")
	fmt.Println("3) 手动粘贴自定义 Image OCID")
	fmt.Print("请选择 [1/2/3]: ")

	choice := readInput()
	if choice == "3" {
		fmt.Print("👉 请粘贴 Image OCID: ")
		return readInput()
	}

	osName, osVersion := "Canonical Ubuntu", "22.04"
	if choice == "2" {
		osName, osVersion = "Oracle Linux", "8"
	}

	fmt.Printf("⏳ 正在云端匹配适配 %s 架构的最新 %s %s...\n", cpuShape, osName, osVersion)

	res, err := computeClient.ListImages(context.Background(), core.ListImagesRequest{
		CompartmentId:          common.String(compartmentID),
		OperatingSystem:        common.String(osName),
		OperatingSystemVersion: common.String(osVersion),
		Shape:                  common.String(cpuShape),
		SortBy:                 core.ListImagesSortByTimecreated,
		SortOrder:              core.ListImagesSortOrderDesc,
		Limit:                  common.Int(1),
	})

	if err != nil || len(res.Items) == 0 {
		fmt.Print("❌ 自动匹配失败，请手动粘贴 Image OCID: ")
		return readInput()
	}

	fmt.Printf("✅ 匹配成功: %s\n", *res.Items[0].DisplayName)
	return *res.Items[0].Id
}

// ============ 风控感知的抢机配置与逻辑 ============
type GrabConfig struct {
	InstanceName                                                                       string
	CPUType, ImageID, BootVolumeID, SubnetID, ADName, RootPassword, StartTime, EndTime string
	Cores, Memory                                                                      float32
	Disk                                                                               int64
	MinDelay, MaxDelay                                                                 int
	BaseDelayMs                                                                        int
	RetryLimit                                                                         int
	ThrottleBackoffFactor                                                              float64
	ResourceBackoffMin                                                                 int
	ResourceBackoffMax                                                                 int
	RequestTimeout                                                                     time.Duration
}

func grabInstanceMenu() {
	conf := GrabConfig{
		BaseDelayMs:           300,
		RetryLimit:            999,
		ThrottleBackoffFactor: 2.0,
		ResourceBackoffMin:    45,
		ResourceBackoffMax:    120,
		RequestTimeout:        20 * time.Second,
	}

	fmt.Println("\n=== 🔧 抢机配置初始化 ===")

	fmt.Print("📝 请输入抢机成功后的【实例名称】(直接回车默认 Oraman-Auto-Grabbed): ")
	conf.InstanceName = readInput()
	if conf.InstanceName == "" {
		conf.InstanceName = "Oraman-Auto-Grabbed"
	}

	fmt.Print("🖥️ CPU [1:ARM(A1.Flex)  2:AMD(E2.1.Micro)]: ")
	if readInput() == "1" {
		conf.CPUType = "VM.Standard.A1.Flex"
		fmt.Print("   核心数 (默认4): ")
		fmt.Scanln(&conf.Cores)
		fmt.Print("   内存 (GB, 默认24): ")
		fmt.Scanln(&conf.Memory)
		readInput()
	} else {
		conf.CPUType = "VM.Standard.E2.1.Micro"
		conf.Cores, conf.Memory = 1, 1
	}

	conf.ADName = selectAvailabilityDomain()
	conf.SubnetID = selectSubnet()
	conf.ImageID = selectImage(conf.CPUType)

	fmt.Print("\n💾 硬盘大小 (GB, 默认50): ")
	fmt.Scanln(&conf.Disk)
	if conf.Disk == 0 {
		conf.Disk = 50
	}
	readInput()

	fmt.Print("📂 请拖入公钥文件 (.pub) 或直接回车跳过: ")
	pubPath := strings.Trim(readInput(), `"'`)
	if pubPath != "" {
		keyContent, err := os.ReadFile(pubPath)
		if err == nil {
			conf.RootPassword = string(keyContent)
			fmt.Println("✅ 公钥已加载！")
		}
	}

	fmt.Print("\n⏱️ 最小防封禁延迟(秒, 推荐 30): ")
	fmt.Scanln(&conf.MinDelay)
	fmt.Print("⏱️ 最大防封禁延迟(秒, 推荐 60): ")
	fmt.Scanln(&conf.MaxDelay)
	readInput()
	if conf.MinDelay <= 0 {
		conf.MinDelay = 1
	}
	if conf.MinDelay > conf.MaxDelay {
		conf.MinDelay, conf.MaxDelay = conf.MaxDelay, conf.MinDelay
	}

	fmt.Print("🕰️ 定时开始时间 (北京时间 00:00，留空即刻开始): ")
	conf.StartTime = readInput()
	if conf.StartTime != "" {
		fmt.Print("🕰️ 定时结束时间 (23:59): ")
		conf.EndTime = readInput()
	}

	fmt.Println("\n✅ 配置就绪，准备发起请求...")
	runTimedGrabLoop(conf)
}

func calculateBackoff(retryCount int, isThrottled bool, isResourceExhausted bool) time.Duration {
	if isThrottled {
		baseSec := math.Min(300, math.Pow(2, float64(retryCount))+float64(rand.Intn(30)))
		return time.Duration(baseSec)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
	}

	if isResourceExhausted {
		delaySec := 45 + rand.Intn(76)
		return time.Duration(delaySec)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
	}

	return time.Duration(100+rand.Intn(200))*time.Millisecond + time.Duration(rand.Intn(5))*time.Second
}

func runTimedGrabLoop(conf GrabConfig) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	consecutiveFail = 0

	for retryCount := 0; retryCount < conf.RetryLimit; retryCount++ {
		now := time.Now().In(loc).Format("15:04")
		if conf.StartTime != "" && (now < conf.StartTime || now > conf.EndTime) {
			fmt.Printf("\r⏳ 等待时段 %s-%s (当前 %s)...", conf.StartTime, conf.EndTime, now)
			time.Sleep(30 * time.Second)
			continue
		}

		fmt.Printf("\n[%s] 🚀 发起请求 #%d (目标: %s)...", time.Now().Format("15:04:05"), retryCount+1, conf.CPUType)
		err := performLaunchInstance(conf)

		if err == nil {
			fmt.Println("\n🎉 [大吉大利] 恭喜，机器抢到了！任务停止。")
			return
		}

		consecutiveFail++
		isThrottled := false
		isResourceExhausted := false

		if svcErr, ok := common.IsServiceError(err); ok {
			statusCode := svcErr.GetHTTPStatusCode()
			errMsg := strings.ToLower(svcErr.GetMessage())

			if statusCode == 500 && (strings.Contains(errMsg, "out of host capacity") || strings.Contains(errMsg, "out of capacity")) {
				fmt.Print(" ⚠️ 资源紧张 (500 无货)")
				isResourceExhausted = true
			} else if statusCode == 429 {
				fmt.Printf(" 🛑 触发限流 (429) - 连续失败%d次", consecutiveFail)
				isThrottled = true
			} else if statusCode == 401 || statusCode == 403 {
				fmt.Printf(" ❌ 认证失败 [%d]", statusCode)
				isThrottled = true
			} else if statusCode == 400 {
				fmt.Printf(" ⚠️ 请求格式错误 [%d]", statusCode)
			} else {
				fmt.Printf(" ❌ API错误 [%d] %s", statusCode, svcErr.GetMessage())
			}
		} else {
			fmt.Printf(" ❌ 网络异常: %v", err)
		}

		backoff := calculateBackoff(consecutiveFail, isThrottled, isResourceExhausted)
		fmt.Printf("\n⏳ 沉默中... %v\n", backoff)
		time.Sleep(backoff)

		if err == nil {
			consecutiveFail = 0
		}
	}

	fmt.Printf("❌ 达到最大重试次数 (%d)，抢机失败\n", conf.RetryLimit)
}

func performLaunchInstance(conf GrabConfig) error {
	var sourceDetails core.InstanceSourceDetails

	// 💡 核心改动：如果传了 BootVolumeID，说明是快照恢复；否则是全新安装
	if conf.BootVolumeID != "" {
		sourceDetails = core.InstanceSourceViaBootVolumeDetails{
			BootVolumeId: common.String(conf.BootVolumeID),
		}
	} else {
		sourceDetails = core.InstanceSourceViaImageDetails{
			ImageId:             common.String(conf.ImageID),
			BootVolumeSizeInGBs: common.Int64(conf.Disk),
		}
	}

	details := core.LaunchInstanceDetails{
		AvailabilityDomain: common.String(conf.ADName),
		CompartmentId:      common.String(compartmentID),
		DisplayName:        common.String(conf.InstanceName),
		Shape:              common.String(conf.CPUType),
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{
			Ocpus:       common.Float32(conf.Cores),
			MemoryInGBs: common.Float32(conf.Memory),
		},
		SourceDetails: sourceDetails,
		CreateVnicDetails: &core.CreateVnicDetails{
			SubnetId:     common.String(conf.SubnetID),
			AssignIpv6Ip: common.Bool(true),
		},
	}

	if strings.HasPrefix(conf.RootPassword, "ssh-") {
		details.Metadata = map[string]string{
			"ssh_authorized_keys": conf.RootPassword,
		}
	} else if conf.RootPassword != "" {
		script := fmt.Sprintf("#!/bin/bash\necho 'root:%s' | chpasswd\nsed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config\nsystemctl restart sshd", conf.RootPassword)
		details.Metadata = map[string]string{"user_data": base64.StdEncoding.EncodeToString([]byte(script))}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := computeClient.LaunchInstance(ctx, core.LaunchInstanceRequest{
		LaunchInstanceDetails: details,
	})
	return err
}

func autoChangeShape(instanceID string, targetCores float32, targetRam float32) {
	fmt.Printf("\n🚀 启动自动盲刷变配任务 (目标: %v核 %vG ARM)...\n", targetCores, targetRam)
	fmt.Println("⚠️ 注意: 变配成功后实例会自动重启一次。请保持程序后台运行。")

	consecutiveFail = 0

	for retryCount := 0; retryCount < 9999; retryCount++ {
		fmt.Printf("\n[%s] 正在向甲骨文提交配置变配请求 #%d...", time.Now().Format("15:04:05"), retryCount+1)

		details := core.UpdateInstanceDetails{
			Shape: common.String("VM.Standard.A1.Flex"),
			ShapeConfig: &core.UpdateInstanceShapeConfigDetails{
				Ocpus:       common.Float32(targetCores),
				MemoryInGBs: common.Float32(targetRam),
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := computeClient.UpdateInstance(ctx, core.UpdateInstanceRequest{
			InstanceId:            common.String(instanceID),
			UpdateInstanceDetails: details,
		})
		cancel()

		if err == nil {
			fmt.Println("\n🎉 [大吉大利] 恭喜！变配请求已被接受！机器正在重启并应用新配置。")
			return
		}

		consecutiveFail++
		isThrottled := false
		isResourceExhausted := false

		if svcErr, ok := common.IsServiceError(err); ok {
			statusCode := svcErr.GetHTTPStatusCode()
			errMsg := strings.ToLower(svcErr.GetMessage())

			if statusCode == 500 && (strings.Contains(errMsg, "out of host capacity") || strings.Contains(errMsg, "out of capacity")) {
				fmt.Print(" ⚠️ 资源紧张 (500 无货)")
				isResourceExhausted = true
			} else if statusCode == 429 {
				fmt.Printf(" 🛑 触发限流 (429) - 连续失败%d次", consecutiveFail)
				isThrottled = true
			} else if statusCode == 401 || statusCode == 403 {
				fmt.Printf(" ❌ 认证失败 [%d]", statusCode)
				isThrottled = true
			} else {
				fmt.Printf(" ❌ API错误 [%d] %s", statusCode, svcErr.GetMessage())
			}
		} else {
			fmt.Printf(" ❌ 网络异常: %v", err)
		}

		backoff := calculateBackoff(consecutiveFail, isThrottled, isResourceExhausted)
		fmt.Printf(" ⏳ 休息 %v\n", backoff)
		time.Sleep(backoff)

		if err == nil {
			consecutiveFail = 0
		}
	}
}

// ============ VCN 安全列表与路由表控制 ============

func vcnSecurityMenu() {
	fmt.Println("\n=== 🛡️ VCN 网络安全与路由控制 ===")

	subnetID := selectSubnet()
	if subnetID == "" || !strings.HasPrefix(subnetID, "ocid1.subnet.") {
		fmt.Println("❌ 未选中有效的子网，操作取消。")
		return
	}

	fmt.Println("\n--- ⚙️ 安全规则操作 ---")
	fmt.Println("1) 🟢 追加放行端口 (安全追加，不影响现有规则)")
	fmt.Println("2) 🔒 严格放行端口 (⚠️ 清空其他所有入站规则，仅留指定端口)")
	fmt.Println("3) 🔴 一键全开端口协议 (高危，清空旧规则并双栈全开)")
	fmt.Println("4) 🌍 修复公网路由 (自动添加 0.0.0.0/0 和 ::/0 到网关)")
	fmt.Println("5) 🌐 为 VCN 与子网开启 IPv6 (底层环境初始化)")
	fmt.Println("6) 🏗️ 荒野拓荒：一键初始化全新网络环境 (创建 VCN/子网/公网网关)")
	fmt.Print("请选择操作 [1/2/3/4/5/6]: ")

	choice := readInput()
	switch choice {
	case "1":
		fmt.Print("👉 请输入要【追加】放行的 TCP 端口 (多个用空格或逗号隔开，如 22 80 443): ")
		ports := parsePortInput(readInput())
		if len(ports) > 0 {
			updateSecurityList(subnetID, ports, "append")
		} else {
			fmt.Println("❌ 未检测到有效端口，操作取消")
		}
	case "2":
		fmt.Print("⚠️ 警告：此操作将删除所有旧入站规则！\n👉 请输入要【唯一保留】的 TCP 端口: ")
		ports := parsePortInput(readInput())
		if len(ports) > 0 {
			updateSecurityList(subnetID, ports, "strict")
		} else {
			fmt.Println("❌ 未检测到有效端口，操作取消")
		}
	case "3":
		fmt.Print("⚠️ 确定要清空旧规则并向全网开放所有端口吗？(y/n): ")
		if readInput() == "y" {
			updateSecurityList(subnetID, nil, "all")
		}
	case "4":
		updateRouteTable(subnetID)
	case "5":
		enableIPv6ForVCNAndSubnet(subnetID)
	case "6":
		autoCreateNetwork()
	default:
		fmt.Println("⚠️ 无效操作")
	}
}

// 核心功能：更新安全列表 (修复出站遗漏与旧规则未清空的问题)
func updateSecurityList(subnetID string, ports []int, mode string) {
	ctx := context.Background()

	subReq := core.GetSubnetRequest{SubnetId: common.String(subnetID)}
	subRes, err := networkClient.GetSubnet(ctx, subReq)
	if err != nil || len(subRes.Subnet.SecurityListIds) == 0 {
		fmt.Printf("❌ 获取子网信息或安全列表失败: %v\n", err)
		return
	}
	secListID := subRes.Subnet.SecurityListIds[0]
	vcnID := subRes.Subnet.VcnId

	hasIPv6 := false
	if vcnID != nil {
		vcnReq := core.GetVcnRequest{VcnId: vcnID}
		vcnRes, vcnErr := networkClient.GetVcn(ctx, vcnReq)
		if vcnErr == nil && len(vcnRes.Vcn.Ipv6CidrBlocks) > 0 {
			hasIPv6 = true
		}
	}

	secReq := core.GetSecurityListRequest{SecurityListId: common.String(secListID)}
	secRes, err := networkClient.GetSecurityList(ctx, secReq)
	if err != nil {
		fmt.Printf("❌ 读取现有安全列表失败: %v\n", err)
		return
	}

	currentIngress := secRes.SecurityList.IngressSecurityRules
	currentEgress := secRes.SecurityList.EgressSecurityRules
	var targetIngress []core.IngressSecurityRule
	var targetEgress []core.EgressSecurityRule

	// ---- 1. 处理入站规则 (Ingress) ----
	if mode == "all" {
		targetIngress = []core.IngressSecurityRule{
			{Source: common.String("0.0.0.0/0"), Protocol: common.String("all"), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock},
		}

		if hasIPv6 {
			targetIngress = append(targetIngress, core.IngressSecurityRule{Source: common.String("::/0"), Protocol: common.String("all"), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock})
			fmt.Println("⏳ 检测到 VCN 已开启 IPv6，正在清空旧规则，覆盖为双栈 [全开] 入站规则...")
		} else {
			fmt.Println("⏳ VCN 未开启 IPv6，正在清空旧规则，覆盖为 IPv4 [全开] 入站规则...")
		}
	} else {
		var portRules []core.IngressSecurityRule
		for _, port := range ports {
			portRules = append(portRules, core.IngressSecurityRule{
				Source:   common.String("0.0.0.0/0"),
				Protocol: common.String("6"),
				TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: common.Int(port), Max: common.Int(port)}},
				SourceType: core.IngressSecurityRuleSourceTypeCidrBlock,
			})
			if hasIPv6 {
				portRules = append(portRules, core.IngressSecurityRule{
					Source:   common.String("::/0"),
					Protocol: common.String("6"),
					TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: common.Int(port), Max: common.Int(port)}},
					SourceType: core.IngressSecurityRuleSourceTypeCidrBlock,
				})
			}
		}

		if mode == "strict" {
			targetIngress = portRules
			if hasIPv6 {
				fmt.Printf("⏳ 正在清空旧规则，强制放行双栈 TCP 端口 %v...\n", ports)
			} else {
				fmt.Printf("⏳ 正在清空旧规则，强制放行 IPv4 TCP 端口 %v...\n", ports)
			}
		} else {
			targetIngress = append(currentIngress, portRules...)
			if len(ports) > 0 {
				fmt.Printf("⏳ 正在追加放行 TCP 端口规则 %v...\n", ports)
			}
		}
	}

	// ---- 2. 处理出站规则 (Egress) ----
	if mode == "all" || mode == "strict" {
		targetEgress = []core.EgressSecurityRule{
			{Destination: common.String("0.0.0.0/0"), Protocol: common.String("all"), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock},
		}
		if hasIPv6 {
			targetEgress = append(targetEgress, core.EgressSecurityRule{
				Destination: common.String("::/0"), Protocol: common.String("all"), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock,
			})
		}
	} else {
		targetEgress = currentEgress
		hasV4E, hasV6E := false, false
		for _, r := range targetEgress {
			if r.Destination != nil {
				if *r.Destination == "0.0.0.0/0" && *r.Protocol == "all" { hasV4E = true }
				if *r.Destination == "::/0" && *r.Protocol == "all" { hasV6E = true }
			}
		}
		if !hasV4E {
			targetEgress = append(targetEgress, core.EgressSecurityRule{
				Destination: common.String("0.0.0.0/0"), Protocol: common.String("all"), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock,
			})
			fmt.Println("➕ 自动补齐 IPv4 出站全开规则...")
		}
		if hasIPv6 && !hasV6E {
			targetEgress = append(targetEgress, core.EgressSecurityRule{
				Destination: common.String("::/0"), Protocol: common.String("all"), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock,
			})
			fmt.Println("➕ 自动补齐 IPv6 出站全开规则...")
		}
	}

	updateReq := core.UpdateSecurityListRequest{
		SecurityListId: common.String(secListID),
		UpdateSecurityListDetails: core.UpdateSecurityListDetails{
			IngressSecurityRules: targetIngress,
			EgressSecurityRules:  targetEgress,
		},
	}

	_, err = networkClient.UpdateSecurityList(ctx, updateReq)
	if err != nil {
		fmt.Printf("❌ 安全列表更新失败: %v\n", err)
	} else {
		fmt.Println("✅ 安全列表更新成功！端口规则已完全同步。")
	}
}

// 核心功能：配置网关与路由表
func updateRouteTable(subnetID string) {
	ctx := context.Background()

	subReq := core.GetSubnetRequest{SubnetId: common.String(subnetID)}
	subRes, err := networkClient.GetSubnet(ctx, subReq)
	if err != nil {
		fmt.Printf("❌ 获取子网信息失败: %v\n", err)
		return
	}
	vcnID := *subRes.Subnet.VcnId
	routeTableID := *subRes.Subnet.RouteTableId

	hasIPv6 := false
	vcnReq := core.GetVcnRequest{VcnId: common.String(vcnID)}
	vcnRes, _ := networkClient.GetVcn(ctx, vcnReq)
	if len(vcnRes.Vcn.Ipv6CidrBlocks) > 0 {
		hasIPv6 = true
	}

	fmt.Println("🔍 正在检索互联网网关 (IGW)...")
	igwReq := core.ListInternetGatewaysRequest{
		CompartmentId: common.String(compartmentID),
		VcnId:         common.String(vcnID),
	}
	igwRes, err := networkClient.ListInternetGateways(ctx, igwReq)
	if err != nil || len(igwRes.Items) == 0 {
		fmt.Println("❌ 找不到互联网网关！请先在网页端为该 VCN 创建 Internet Gateway。")
		return
	}
	igwID := *igwRes.Items[0].Id

	rtReq := core.GetRouteTableRequest{RtId: common.String(routeTableID)}
	rtRes, err := networkClient.GetRouteTable(ctx, rtReq)
	if err != nil {
		fmt.Printf("❌ 读取路由表失败: %v\n", err)
		return
	}

	currentRules := rtRes.RouteTable.RouteRules
	hasIPv4Rt, hasIPv6Rt := false, false

	for _, rule := range currentRules {
		if rule.Destination != nil {
			if *rule.Destination == "0.0.0.0/0" { hasIPv4Rt = true }
			if *rule.Destination == "::/0" { hasIPv6Rt = true }
		}
	}

	needUpdate := false
	if !hasIPv4Rt {
		currentRules = append(currentRules, core.RouteRule{
			NetworkEntityId: common.String(igwID), Destination: common.String("0.0.0.0/0"), DestinationType: core.RouteRuleDestinationTypeCidrBlock,
		})
		fmt.Println("➕ 追加 IPv4 默认网关路由...")
		needUpdate = true
	}
	if hasIPv6 && !hasIPv6Rt {
		currentRules = append(currentRules, core.RouteRule{
			NetworkEntityId: common.String(igwID), Destination: common.String("::/0"), DestinationType: core.RouteRuleDestinationTypeCidrBlock,
		})
		fmt.Println("➕ 追加 IPv6 默认网关路由...")
		needUpdate = true
	}

	if !needUpdate {
		fmt.Println("✅ 路由表中已配置好正确的网关路由，无需修改。")
		return
	}

	updateReq := core.UpdateRouteTableRequest{
		RtId: common.String(routeTableID),
		UpdateRouteTableDetails: core.UpdateRouteTableDetails{RouteRules: currentRules},
	}
	_, err = networkClient.UpdateRouteTable(ctx, updateReq)
	if err != nil {
		fmt.Printf("❌ 路由表更新失败: %v\n", err)
	} else {
		fmt.Println("✅ 路由表修复成功！网络出站及 IPv6 已指向公网。")
	}
}

// 核心功能：一键为 VCN 和子网分配 IPv6 (新增自动配置路由逻辑)
func enableIPv6ForVCNAndSubnet(subnetID string) {
	fmt.Println("\n=== 🌐 一键开启 VCN 与子网 IPv6 ===")

	ctx := context.Background()

	subReq := core.GetSubnetRequest{SubnetId: common.String(subnetID)}
	subRes, err := networkClient.GetSubnet(ctx, subReq)
	if err != nil {
		fmt.Printf("❌ 获取子网信息失败: %v\n", err)
		return
	}
	vcnID := subRes.Subnet.VcnId

	vcnReq := core.GetVcnRequest{VcnId: vcnID}
	vcnRes, err := networkClient.GetVcn(ctx, vcnReq)
	if err != nil {
		fmt.Printf("❌ 获取 VCN 信息失败: %v\n", err)
		return
	}

	var vcnIPv6Prefix string
	if len(vcnRes.Vcn.Ipv6CidrBlocks) > 0 {
		vcnIPv6Prefix = vcnRes.Vcn.Ipv6CidrBlocks[0]
		fmt.Printf("✅ VCN 已开启 IPv6，前缀为: %s\n", vcnIPv6Prefix)
	} else {
		fmt.Println("⏳ 正在向 Oracle 申请免费的 IPv6 CIDR (/56) 分配给 VCN...")

		addReq := core.AddIpv6VcnCidrRequest{VcnId: vcnID}
		_, err = networkClient.AddIpv6VcnCidr(ctx, addReq)
		if err != nil {
			fmt.Printf("❌ 无法为 VCN 分配 IPv6: %v\n", err)
			return
		}

		vcnRes, _ = networkClient.GetVcn(ctx, vcnReq)
		if len(vcnRes.Vcn.Ipv6CidrBlocks) > 0 {
			vcnIPv6Prefix = vcnRes.Vcn.Ipv6CidrBlocks[0]
			fmt.Printf("🎉 VCN IPv6 申请成功: %s\n", vcnIPv6Prefix)
		} else {
			fmt.Println("❌ VCN IPv6 申请未生效。")
			return
		}
	}

	if len(subRes.Subnet.Ipv6CidrBlocks) > 0 {
		fmt.Printf("✅ 子网已配置 IPv6，CIDR 为: %s\n", subRes.Subnet.Ipv6CidrBlocks[0])
	} else {
		fmt.Println("⏳ 正在为子网划分并分配 IPv6 CIDR (/64)...")
		prefixBase := strings.Split(vcnIPv6Prefix, "::/56")[0]
		subnetIPv6Cidr := prefixBase + "::/64"

		updateSubReq := core.UpdateSubnetRequest{
			SubnetId: common.String(subnetID),
			UpdateSubnetDetails: core.UpdateSubnetDetails{Ipv6CidrBlocks: []string{subnetIPv6Cidr}},
		}

		_, err = networkClient.UpdateSubnet(ctx, updateSubReq)
		if err != nil {
			fmt.Printf("❌ 为子网分配 IPv6 失败: %v\n", err)
			return
		}
		fmt.Printf("🎉 子网 IPv6 分配成功: %s\n", subnetIPv6Cidr)
	}

	// 🚀 一条龙服务：自动触发路由与出站修复
	fmt.Println("\n🔧 正在为您后台自动配置 IPv6 网关路由与出站安全规则...")
	time.Sleep(2 * time.Second)
	updateRouteTable(subnetID)
	updateSecurityList(subnetID, nil, "append")

	fmt.Println("\n👉 提示：IPv6 基础设施及路由已彻底打通！(如果需要入站端口全开，可直接选择菜单 3 执行)")
}

// ============ 实例重装回 Ubuntu 20.04 (防 200G 超额风控版) ============
func rebuildToUbuntu2004(inst core.Instance) {
	fmt.Println("\n=== 🔄 Win11 彻底重装回原版 Ubuntu 20.04 (删机重建法) ===")
	fmt.Println("⚠️ 核心 API 限制警告：")
	fmt.Println("甲骨文云 (OCI) 不允许在没有 Compute 实例的情况下，直接通过系统镜像创建引导卷。")
	fmt.Println("因此，目前唯一能换回官方 Ubuntu 且【绝不超 200G 限额】的方法是：")
	fmt.Println("1. 提取当前实例参数，随后连同 Win11 引导卷一起彻底删除。")
	fmt.Println("2. 强制等待 2 分钟，确保云端底层彻底释放 200G 免费硬盘配额。")
	fmt.Println("3. 自动调用本程序的【自动抢机模块】高频将原规格实例抢回来。")
	fmt.Println("⚠️ 风险提示：在释放配额的 2 分钟内，您的 ARM 资源有极小概率被同区域的其他人截胡！")
	fmt.Print("\n👉 确定要执行此危险操作吗？请在此输入大写 YES 确认: ")

	if readInput() != "YES" {
		fmt.Println("❌ 操作已取消。")
		return
	}

	ctx := context.Background()
	insID := *inst.Id

	// 1. 获取基础网络与规格配置，为后续重建无缝衔接做准备
	fmt.Println("\n⏳ [1/4] 正在提取当前实例的网络与规格参数，用于自动重建...")
	var subnetID string
	vnicReq := core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(compartmentID),
		InstanceId:    common.String(insID),
	}
	vnicRes, err := computeClient.ListVnicAttachments(ctx, vnicReq)
	if err == nil && len(vnicRes.Items) > 0 && vnicRes.Items[0].SubnetId != nil {
		subnetID = *vnicRes.Items[0].SubnetId
	} else {
		fmt.Println("❌ 无法获取绑定的子网信息，重建配置缺失，操作已中止以保护您的实例。")
		return
	}

	cpuShape := *inst.Shape
	cores := float32(1.0)
	ram := float32(1.0)
	if inst.ShapeConfig != nil {
		if inst.ShapeConfig.Ocpus != nil {
			cores = *inst.ShapeConfig.Ocpus
		}
		if inst.ShapeConfig.MemoryInGBs != nil {
			ram = *inst.ShapeConfig.MemoryInGBs
		}
	}
	ad := *inst.AvailabilityDomain

	// 匹配区域最新的 Ubuntu 20.04 镜像
	fmt.Printf("⏳ 正在匹配当前架构 (%s) 的 Canonical Ubuntu 20.04 镜像...\n", cpuShape)
	imgReq := core.ListImagesRequest{
		CompartmentId:          common.String(compartmentID),
		OperatingSystem:        common.String("Canonical Ubuntu"),
		OperatingSystemVersion: common.String("20.04"),
		Shape:                  common.String(cpuShape),
		SortBy:                 core.ListImagesSortByTimecreated,
		SortOrder:              core.ListImagesSortOrderDesc,
		Limit:                  common.Int(1),
	}
	imgRes, err := computeClient.ListImages(ctx, imgReq)
	if err != nil || len(imgRes.Items) == 0 {
		fmt.Println("❌ 自动匹配 Ubuntu 镜像失败，请确认 API 权限或区域镜像库状态。")
		return
	}
	imageID := *imgRes.Items[0].Id
	fmt.Printf("✅ 匹配成功: %s\n", *imgRes.Items[0].DisplayName)

	// 2. 彻底删除原实例与硬盘
	fmt.Println("\n⏳ [2/4] 正在下发指令：彻底删除原实例与 Win11 引导卷...")
	_, err = computeClient.TerminateInstance(ctx, core.TerminateInstanceRequest{
		InstanceId:         common.String(insID),
		PreserveBootVolume: common.Bool(false), // 绝对关键：这里必须是 false，连盘一起删
	})
	if err != nil {
		fmt.Printf("❌ 删除失败: %v\n", err)
		return
	}

	// 3. 强制等待配额释放
	fmt.Println("\n⏳ [3/4] 实例已离线！防超额风控生效：强制休眠 120 秒，等待甲骨文云端清理 200GB 存储账单...")
	for i := 120; i > 0; i-- {
		fmt.Printf("\r倒计时: %d 秒...", i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("\r✅ 配额刷新期结束！空间已清零。                                 ")

	// 4. 交接给底层的抢机循环模块
	fmt.Println("\n🚀 [4/4] 正在将配置注入高频抢机模块，尝试夺回实例资源...")
	conf := GrabConfig{
		InstanceName:          *inst.DisplayName + "-Recovered", // 自动给名字加后缀防重复
		CPUType:               cpuShape,
		ImageID:               imageID,
		SubnetID:              subnetID,
		ADName:                ad,
		Cores:                 cores,
		Memory:                ram,
		Disk:                  50, // 恢复到健康的 50G
		MinDelay:              3,  // 抢机延迟调低，尽快抢回
		MaxDelay:              8,
		BaseDelayMs:           300,
		RetryLimit:            9999, // 盲刷直到抢到为止
		ThrottleBackoffFactor: 2.0,
		ResourceBackoffMin:    5,
		ResourceBackoffMax:    15,
	}

	runTimedGrabLoop(conf)
}

// ============ 扩容实例硬盘 ============
func resizeBootVolume(inst core.Instance) {
	fmt.Println("\n=== 💾 实例硬盘扩容 ===")
	fmt.Println("⚠️ 注意事项：")
	fmt.Println("1. 甲骨文云 API 仅支持【扩大】硬盘，绝不支持【缩小】！")
	fmt.Println("2. 免费层级 (Always Free) 的总硬盘限额是 200GB (包含所有实例总和)。")
	fmt.Println("3. 扩容后，需要在服务器系统内部执行扩容命令才能生效。")

	ctx := context.Background()
	insID := *inst.Id
	ad := *inst.AvailabilityDomain

	// 1. 获取当前绑定的引导卷信息
	fmt.Println("\n⏳ 正在查询当前硬盘大小...")
	attachReq := core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: common.String(ad),
		CompartmentId:      common.String(compartmentID),
		InstanceId:         common.String(insID),
	}
	attachRes, err := computeClient.ListBootVolumeAttachments(ctx, attachReq)
	if err != nil || len(attachRes.Items) == 0 {
		fmt.Println("❌ 获取引导卷挂载记录失败，请检查实例是否正常运行。")
		return
	}

	bootVolID := attachRes.Items[0].BootVolumeId
	bvReq := core.GetBootVolumeRequest{BootVolumeId: bootVolID}
	bvRes, err := blockStorageClient.GetBootVolume(ctx, bvReq)
	if err != nil || bvRes.BootVolume.SizeInGBs == nil {
		fmt.Println("❌ 无法读取当前硬盘详细信息。")
		return
	}

	currentSize := *bvRes.BootVolume.SizeInGBs
	fmt.Printf("✅ 找到引导卷 OCID: ...%s\n", (*bootVolID)[len(*bootVolID)-15:])
	fmt.Printf("✅ 当前硬盘物理容量为: %d GB\n", currentSize)

	// 2. 接收用户输入
	fmt.Print("\n👉 请输入目标硬盘大小 (GB)，必须大于当前大小 (例如 100, 150, 200): ")
	inputSizeStr := readInput()
	newSize, err := strconv.ParseInt(inputSizeStr, 10, 64)
	if err != nil {
		fmt.Println("❌ 输入无效，请输入纯数字。")
		return
	}

	// 安全校验
	if newSize <= currentSize {
		fmt.Printf("❌ 错误：目标大小 (%d GB) 必须严格大于当前大小 (%d GB)！\n", newSize, currentSize)
		return
	}
	if newSize > 200 {
		fmt.Println("⚠️ 警告：您设定的硬盘大小超过了 200GB！如果您是未升级的纯免费账户，这将会直接报错。")
		fmt.Print("👉 确定要继续提交请求吗？(y/n): ")
		if readInput() != "y" {
			fmt.Println("❌ 已取消操作。")
			return
		}
	}

	// 3. 执行扩容
	fmt.Printf("\n⏳ 正在向 Oracle 提交物理硬盘扩容请求 (%d GB -> %d GB)...\n", currentSize, newSize)
	updateReq := core.UpdateBootVolumeRequest{
		BootVolumeId: bootVolID,
		UpdateBootVolumeDetails: core.UpdateBootVolumeDetails{
			SizeInGBs: common.Int64(newSize),
		},
	}

	_, err = blockStorageClient.UpdateBootVolume(ctx, updateReq)
	if err != nil {
		fmt.Printf("❌ 硬盘扩容 API 调用失败: %v\n", err)
		return
	}

	fmt.Println("🎉 扩容请求已成功下发！云端后台正在为您分配存储空间。")
	fmt.Println("👉 甲骨文云端扩容通常需要 1 分钟左右。")

	fmt.Println("\n=======================================================")
	fmt.Println("🛠️ 【重要收尾操作】物理硬盘虽然变大了，但系统分区还没变大！")
	fmt.Println("请在稍后 SSH 登录进服务器后，手动执行以下一键扩容命令：")
	fmt.Println("Ubuntu 系统执行:  sudo /usr/libexec/oci-growfs")
	fmt.Println("或者通用原生命令: sudo growpart /dev/sda 1 && sudo resize2fs /dev/sda1")
	fmt.Println("=======================================================")
}

// ============ 引导卷与备份管理 ============

// 辅助函数：获取实例绑定的引导卷 ID
func getBootVolumeID(instanceID string, ad string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: common.String(ad),
		CompartmentId:      common.String(compartmentID),
		InstanceId:         common.String(instanceID),
	}
	res, err := computeClient.ListBootVolumeAttachments(ctx, req)
	if err != nil || len(res.Items) == 0 {
		return ""
	}
	return *res.Items[0].BootVolumeId
}

// 核心功能：创建引导卷快照备份
func createBootVolumeBackup(inst core.Instance) {
	fmt.Println("\n=== 📸 创建系统快照备份 (云端 Ghost) ===")
	ad := *inst.AvailabilityDomain
	bvID := getBootVolumeID(*inst.Id, ad)

	if bvID == "" {
		fmt.Println("❌ 获取引导卷失败，请检查实例是否正常运行。")
		return
	}

	backupName := *inst.DisplayName + "-Backup-" + time.Now().Format("0102-1504")
	fmt.Printf("⏳ 正在为硬盘下发备份指令 (备份名: %s)...\n", backupName)

	req := core.CreateBootVolumeBackupRequest{
		CreateBootVolumeBackupDetails: core.CreateBootVolumeBackupDetails{
			BootVolumeId: common.String(bvID),
			DisplayName:  common.String(backupName),
			Type:         core.CreateBootVolumeBackupDetailsTypeFull,
		},
	}

	_, err := blockStorageClient.CreateBootVolumeBackup(context.Background(), req)
	if err != nil {
		fmt.Printf("❌ 创建备份失败: %v\n", err)
		return
	}

	fmt.Println("🎉 备份指令下发成功！甲骨文云端正在后台悄悄打包。")
	fmt.Println("👉 提示：由于是热备份，完全不影响您的服务器运行。您可以在网页端查看备份进度。")
}

// 核心功能：从快照备份无损恢复
func restoreFromBackup(inst core.Instance) {
	fmt.Println("\n=== ⏪ 从系统备份恢复 (规避风控法) ===")
	ctx := context.Background()

	// 1. 获取现有备份列表
	fmt.Println("⏳ 正在拉取您账号下的系统快照列表...")
	req := core.ListBootVolumeBackupsRequest{
		CompartmentId:  common.String(compartmentID),
		LifecycleState: core.BootVolumeBackupLifecycleStateAvailable,
	}
	res, err := blockStorageClient.ListBootVolumeBackups(ctx, req)
	if err != nil || len(res.Items) == 0 {
		fmt.Println("❌ 您的账号下没有发现任何可用的快照备份！请先使用 [选项12] 制作备份。")
		return
	}

	var availableBackups []core.BootVolumeBackup
	fmt.Println("\n=== 📸 可用快照备份列表 ===")
	for i, backup := range res.Items {
		fmt.Printf("[%d] %s | 容量: %vGB | 时间: %s\n", i+1, *backup.DisplayName, *backup.SizeInGBs, backup.TimeCreated.Format("2006-01-02 15:04"))
		availableBackups = append(availableBackups, backup)
	}

	fmt.Print("\n👉 请输入要恢复的备份 [序号] (输入 0 取消): ")
	input := readInput()
	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(availableBackups) {
		fmt.Println("❌ 操作已取消。")
		return
	}
	selectedBackup := availableBackups[idx-1]
	backupID := *selectedBackup.Id
	backupName := *selectedBackup.DisplayName

	// 2. 参数提取与风险确认
	fmt.Println("\n⚠️ 核心警告：")
	fmt.Println("甲骨文免费账号总硬盘限额为 200GB。如果您在不删原机的情况下恢复备份，大概率会因超出限额而报错。")
	fmt.Println("本工具将执行全自动流水线操作：")
	fmt.Println("1) 提取当前实例参数并【彻底删除】当前实例和它的系统盘。")
	fmt.Println("2) 从所选快照克隆出一个全新的系统盘。")
	fmt.Println("3) 呼叫【抢机模块】原地复活，用新系统盘装回原机器配置中。")
	fmt.Print("\n👉 确定要执行此操作吗？请在此输入大写 YES 确认: ")
	if readInput() != "YES" {
		fmt.Println("❌ 操作已取消。")
		return
	}

	insID := *inst.Id
	cpuShape := *inst.Shape
	cores, ram := float32(1.0), float32(1.0)
	if inst.ShapeConfig != nil {
		if inst.ShapeConfig.Ocpus != nil {
			cores = *inst.ShapeConfig.Ocpus
		}
		if inst.ShapeConfig.MemoryInGBs != nil {
			ram = *inst.ShapeConfig.MemoryInGBs
		}
	}
	ad := *inst.AvailabilityDomain

	var subnetID string
	vnicReq := core.ListVnicAttachmentsRequest{CompartmentId: common.String(compartmentID), InstanceId: common.String(insID)}
	vnicRes, _ := computeClient.ListVnicAttachments(ctx, vnicReq)
	if len(vnicRes.Items) > 0 && vnicRes.Items[0].SubnetId != nil {
		subnetID = *vnicRes.Items[0].SubnetId
	} else {
		fmt.Println("❌ 无法提取当前网络配置，恢复操作已保护性中止。")
		return
	}

	// 3. 删除旧机器
	fmt.Println("\n⏳ [1/4] 正在下发指令：彻底删除原实例与引导卷以释放免费配额...")
	_, err = computeClient.TerminateInstance(ctx, core.TerminateInstanceRequest{
		InstanceId:         common.String(insID),
		PreserveBootVolume: common.Bool(false), // 必须为false，连盘一起删
	})
	if err != nil {
		fmt.Printf("❌ 删除失败: %v\n", err)
		return
	}

	// 4. 等待配额刷新
	fmt.Println("\n⏳ [2/4] 强制休眠 60 秒，等待甲骨文云端清理存储账单 (防止 200G 额度未释放报错)...")
	for i := 60; i > 0; i-- {
		fmt.Printf("\r倒计时: %d 秒...", i)
		time.Sleep(1 * time.Second)
	}

	// 5. 从快照克隆硬盘
	fmt.Println("\n\n⏳ [3/4] 正在从备份快照合成新的硬盘 (这可能需要 1~3 分钟)...")
	newBootVolReq := core.CreateBootVolumeRequest{
		CreateBootVolumeDetails: core.CreateBootVolumeDetails{
			AvailabilityDomain: common.String(ad),
			CompartmentId:      common.String(compartmentID),
			DisplayName:        common.String(backupName + "-Restored"),
			SourceDetails:      core.BootVolumeSourceFromBootVolumeBackupDetails{Id: common.String(backupID)},
		},
	}
	newBootVolRes, err := blockStorageClient.CreateBootVolume(ctx, newBootVolReq)
	if err != nil {
		fmt.Printf("❌ 硬盘恢复失败: %v\n🚨 请登录网页端手动通过备份创建实例！\n", err)
		return
	}
	newBootVolumeID := *newBootVolRes.BootVolume.Id

	// 轮询检查硬盘合成状态
	waitSec := 0
	for {
		bvRes, _ := blockStorageClient.GetBootVolume(ctx, core.GetBootVolumeRequest{BootVolumeId: common.String(newBootVolumeID)})
		if bvRes.BootVolume.LifecycleState == core.BootVolumeLifecycleStateAvailable {
			break
		}
		waitSec += 5
		fmt.Printf("\r⏳ 已等待 %d 秒，云端正在合成数据...", waitSec)
		time.Sleep(5 * time.Second)
	}

	// 6. 调用底层抢机模块原地复活
	fmt.Println("\n✅ 硬盘克隆完毕！")
	fmt.Println("🚀 [4/4] 正在呼叫抢机模块，将系统挂载回原规格机器...")

	conf := GrabConfig{
		InstanceName:          *inst.DisplayName + "-Restored",
		CPUType:               cpuShape,
		BootVolumeID:          newBootVolumeID, // 核心：让机器从这个新盘启动
		SubnetID:              subnetID,
		ADName:                ad,
		Cores:                 cores,
		Memory:                ram,
		MinDelay:              3,
		MaxDelay:              8,
		BaseDelayMs:           300,
		RetryLimit:            9999,
		ThrottleBackoffFactor: 2.0,
		ResourceBackoffMin:    5,
		ResourceBackoffMax:    15,
	}

	runTimedGrabLoop(conf)
}

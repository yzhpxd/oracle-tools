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
	computeClient  core.ComputeClient
	networkClient  core.VirtualNetworkClient
	identityClient identity.IdentityClient
	config         common.ConfigurationProvider
	compartmentID  string
	reader         = bufio.NewReader(os.Stdin)

	// 👑 风控追踪变量
	lastFailTime    time.Time
	consecutiveFail int
)

// 辅助函数：安全读取输入
func readInput() string {
	str, _ := reader.ReadString('\n')
	return strings.TrimSpace(str)
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
		fmt.Println("1) 实例管理 (开关机 / 重启 / 彻底删除 / 换IP / 自动升级)")
		fmt.Println("2) 自动抢机 (定时调度 / 随机延迟 / 防封禁 / 自动IPv6)")
		fmt.Println("0) 退出")
		fmt.Print("请选择 [1/2/0]: ")

		switch readInput() {
		case "1":
			instanceManagerMenu()
		case "2":
			grabInstanceMenu()
		case "0":
			fmt.Println("👋 退出程序...")
			os.Exit(0)
		default:
			fmt.Println("⚠️ 无效选择，请重新输入")
		}
	}
}

// ============ 👑 改进 1：IPv6 增强查询机制 ============
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

		// 【第一步】获取 VNIC 基本信息
		vnicReq := core.GetVnicRequest{VnicId: vnicID}
		vnicRes, err := networkClient.GetVnic(context.Background(), vnicReq)
		if err != nil {
			continue
		}

		// 提取 IPv4
		if vnicRes.Vnic.PublicIp != nil && *vnicRes.Vnic.PublicIp != "" {
			ipv4List = append(ipv4List, *vnicRes.Vnic.PublicIp)
		}

		// 【第二步】通过 ListIpv6s 查询 IPv6（主要方法）
		// 使用超时上下文防止某些API操作挂住
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

	// 【第三步】格式化输出
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

// 👑 新增：查询所有 IPv6 地址详细信息
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

		// 获取 VNIC 详情
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

		// 查询 IPv6 地址（改进版，带超时）
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

	// 👑 改进 2：更完善的 User-Agent 伪装
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
		// 👑 新增：反爬虫头
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)))
		return nil
	}

	networkClient, err = core.NewVirtualNetworkClientWithConfigurationProvider(config)
	identityClient, err = identity.NewIdentityClientWithConfigurationProvider(config)

	compartmentID = tenancy
	fmt.Println("✅ 身份验证已就绪，配置及私钥加载成功 (已开启动态指纹伪装)！")
}

// -------- 辅助函数：真正的轮换 IP API 逻辑 --------
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

// -------- 模块 2：实例管理 --------
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
	if idx, err := strconv.Atoi(input); err == nil && idx > 0 && idx <= len(activeInstances) {
		insID = *activeInstances[idx-1].Id
		fmt.Printf("\n✅ 已选中实例: %s\n", *activeInstances[idx-1].DisplayName)
	} else {
		insID = input
		if !strings.HasPrefix(insID, "ocid1.instance.") {
			fmt.Println("❌ 无效输入，OCID 格式错误或序号超出范围。")
			return
		}
		fmt.Println("\n✅ 已选中目标 OCID")
	}

	fmt.Println("\n--- ⚙️ 实例控制中心 ---")
	fmt.Println("1) 正常重启 (SOFTRESET)  2) 强制重启 (HARDRESET)")
	fmt.Println("3) 启动实例 (START)      4) 停止实例 (STOP)")
	fmt.Println("5) 彻底删除 (TERMINATE)  6) 🔄 自动换 IP (盲刷到通为止)")
	fmt.Println("7) 🚀 自动盲刷升级 (1核6G 升级为 4核24G ARM)")
	fmt.Println("8) 📊 查看详细 IP 信息")
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
		autoUpgradeShape(insID)
	case "8":
		getAllInstanceIPDetails(insID)
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

// -------- 模块 3：API 自动发现资源 --------
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

func selectSubnet() string {
	fmt.Println("\n⏳ 正在拉取虚拟云网络 (VCN) 子网列表...")
	res, err := networkClient.ListSubnets(context.Background(), core.ListSubnetsRequest{
		CompartmentId: common.String(compartmentID),
	})

	if err != nil || len(res.Items) == 0 {
		fmt.Print("❌ 无法自动获取子网，请手动粘贴 Subnet OCID: ")
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

// ============ 👑 改进 3：风控感知的抢机配置与逻辑 ============
type GrabConfig struct {
	InstanceName                                                         string
	CPUType, ImageID, SubnetID, ADName, RootPassword, StartTime, EndTime string
	Cores, Memory                                                        float32
	Disk                                                                 int64
	MinDelay, MaxDelay                                                   int
	// 👑 新增：风控自适应参数
	BaseDelayMs            int           // 基础延迟（毫秒）
	RetryLimit             int           // 最大重试次数
	ThrottleBackoffFactor  float64       // 风控退避倍数 (429/401时)
	ResourceBackoffMin     int           // 资源不足时最小等待秒数
	ResourceBackoffMax     int           // 资源不足时最大等待秒数
	RequestTimeout         time.Duration // 单个请求超时时间
}

func grabInstanceMenu() {
	conf := GrabConfig{
		// 👑 风控默认参数
		BaseDelayMs:           300,       // 基础300ms延迟
		RetryLimit:            999,       // 无限重试
		ThrottleBackoffFactor: 2.0,       // 429时翻倍退避
		ResourceBackoffMin:    45,        // 资源不足时等45秒
		ResourceBackoffMax:    120,       // 最多等120秒
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

// 👑 改进：智能退避计算
func calculateBackoff(retryCount int, isThrottled bool, isResourceExhausted bool) time.Duration {
	if isThrottled {
		// 429/401：指数退避 + 随机抖动
		baseSec := math.Min(300, math.Pow(2, float64(retryCount))+float64(rand.Intn(30)))
		return time.Duration(baseSec)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
	}

	if isResourceExhausted {
		// 500 + "out of capacity"：均匀随机等待
		delaySec := 45 + rand.Intn(76) // 45-120秒
		return time.Duration(delaySec)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
	}

	// 其他错误：短延迟 + 随机
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
				isThrottled = true // 认证失败也当成风控处理

			} else if statusCode == 400 {
				fmt.Printf(" ⚠️ 请求格式错误 [%d]", statusCode)
				// 400通常不是风控，可能是配置问题，使用短延迟

			} else {
				fmt.Printf(" ❌ API错误 [%d] %s", statusCode, svcErr.GetMessage())
			}
		} else {
			fmt.Printf(" ❌ 网络异常: %v", err)
		}

		backoff := calculateBackoff(consecutiveFail, isThrottled, isResourceExhausted)
		fmt.Printf("\n⏳ 沉默中... %v\n", backoff)
		time.Sleep(backoff)

		// 👑 每成功一次请求就重置计数
		if err == nil {
			consecutiveFail = 0
		}
	}

	fmt.Printf("❌ 达到最大重试次数 (%d)，抢机失败\n", conf.RetryLimit)
}

func performLaunchInstance(conf GrabConfig) error {
	details := core.LaunchInstanceDetails{
		AvailabilityDomain: common.String(conf.ADName),
		CompartmentId:      common.String(compartmentID),
		DisplayName:        common.String(conf.InstanceName),
		Shape:              common.String(conf.CPUType),
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{
			Ocpus:       common.Float32(conf.Cores),
			MemoryInGBs: common.Float32(conf.Memory),
		},
		SourceDetails: core.InstanceSourceViaImageDetails{
			ImageId:             common.String(conf.ImageID),
			BootVolumeSizeInGBs: common.Int64(conf.Disk),
		},
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

func autoUpgradeShape(instanceID string) {
	fmt.Println("\n🚀 启动自动盲刷升级任务 (目标: 4核24G ARM)...")
	fmt.Println("⚠️ 注意: 升级成功后实例会自动重启一次。请保持程序后台运行。")

	consecutiveFail = 0

	for retryCount := 0; retryCount < 9999; retryCount++ {
		fmt.Printf("\n[%s] 正在向甲骨文提交配置升级请求 #%d...", time.Now().Format("15:04:05"), retryCount+1)

		details := core.UpdateInstanceDetails{
			Shape: common.String("VM.Standard.A1.Flex"),
			ShapeConfig: &core.UpdateInstanceShapeConfigDetails{
				Ocpus:       common.Float32(4),
				MemoryInGBs: common.Float32(24),
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := computeClient.UpdateInstance(ctx, core.UpdateInstanceRequest{
			InstanceId:            common.String(instanceID),
			UpdateInstanceDetails: details,
		})
		cancel()

		if err == nil {
			fmt.Println("\n🎉 [大吉大利] 恭喜！升级请求已被接受！机器正在重启并应用新配置。")
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

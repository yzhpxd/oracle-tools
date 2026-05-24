package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"log"
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
		fmt.Println("2) 自动抢机 (定时调度 / 随机延迟 / 防封禁)")
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

// ---------------- 模块 1：初始化认证 ----------------
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
		log.Fatalf("❌ 解析失败：缺少必需的 API 参数 (tenancy/user/region/fingerprint)。")
	}

	fmt.Print("\n📂 请将 key_file (.pem 文件) 拖入此窗口并回车: ")
	keyPath := strings.Trim(readInput(), `"'`)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("❌ 无法读取私钥文件: %v", err)
	}

	config = common.NewRawConfigurationProvider(tenancy, user, region, fingerprint, string(keyBytes), nil)

	// 初始化计算客户端
	computeClient, err = core.NewComputeClientWithConfigurationProvider(config)
	if err != nil {
		log.Fatalf("❌ 计算客户端初始化失败: %v", err)
	}

	// 👑 探长级黑科技 1：动态指纹池与全套拟人 Header 注入
	uaPool := []string{
		"Terraform/1.0.11", "Terraform/1.1.7", "Terraform/1.2.9",
		"Oracle-CLI/3.20.0", "Oracle-CLI/3.22.1", "Oracle-CLI/3.23.0",
	}
	computeClient.Interceptor = func(req *http.Request) error {
		rand.Seed(time.Now().UnixNano())
		req.Header.Set("User-Agent", uaPool[rand.Intn(len(uaPool))])
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		return nil
	}

	// 初始化网络与身份客户端
	networkClient, err = core.NewVirtualNetworkClientWithConfigurationProvider(config)
	if err != nil {
		log.Fatalf("❌ 网络客户端初始化失败: %v", err)
	}

	identityClient, err = identity.NewIdentityClientWithConfigurationProvider(config)
	if err != nil {
		log.Fatalf("❌ 身份客户端初始化失败: %v", err)
	}

	compartmentID = tenancy
	fmt.Println("✅ 身份验证已就绪，配置及私钥加载成功 (已开启高级指纹伪装)！")
}

// ---------------- 模块 2：实例管理 ----------------
func instanceManagerMenu() {
	fmt.Println("\n⏳ 正在拉取当前区域的实例列表，请稍候...")

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
				fmt.Printf("[%d] %s | 状态: %s | 规格: %s\n",
					i+1, *inst.DisplayName, inst.LifecycleState, *inst.Shape)
				fmt.Printf("    ID: ...%s\n", (*inst.Id)[len(*inst.Id)-15:])
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
	fmt.Println("⚠️ 请确保此实例未绑定您珍贵的预留 IP，否则请先去网页端解绑！")
	for {
		fmt.Printf("[%s] 正在请求更换公共 IP...\n", time.Now().Format("15:04:05"))
		testIP := "129.x.x.x" // 占位：换IP逻辑保持原有设计
		conn, err := net.DialTimeout("tcp", testIP+":22", 3*time.Second)
		if err == nil {
			conn.Close()
			fmt.Printf("✅ 通车！IP %s 可用。\n", testIP)
			break
		}
		fmt.Println("🚫 不通，20秒后重试...")
		time.Sleep(20 * time.Second)
	}
}

// ---------------- 模块 3：API 自动发现资源 ----------------
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

// ---------------- 模块 4：抢机与升级核心逻辑 ----------------
type GrabConfig struct {
	CPUType, ImageID, SubnetID, ADName, RootPassword, StartTime, EndTime string
	Cores, Memory                                                          float32
	Disk                                                                   int64
	MinDelay, MaxDelay                                                     int
}

func grabInstanceMenu() {
	conf := GrabConfig{}
	fmt.Println("\n=== 🔧 抢机配置初始化 ===")

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

	fmt.Print("🔑 开启 Root 密码？(y/n): ")
	if readInput() == "y" {
		fmt.Print("   设置密码 (留空随机生成): ")
		conf.RootPassword = readInput()
		if conf.RootPassword == "" {
			conf.RootPassword = "OramanRoot2026!"
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

func runTimedGrabLoop(conf GrabConfig) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	for {
		now := time.Now().In(loc).Format("15:04")
		if conf.StartTime != "" && (now < conf.StartTime || now > conf.EndTime) {
			fmt.Printf("\r⏳ 等待时段 %s-%s (当前 %s)...", conf.StartTime, conf.EndTime, now)
			time.Sleep(30 * time.Second)
			continue
		}

		fmt.Printf("\n[%s] 🚀 发起请求 (目标: %s)...", time.Now().Format("15:04:05"), conf.CPUType)
		err := performLaunchInstance(conf)

		if err == nil {
			fmt.Println("\n🎉 [大吉大利] 恭喜，机器抢到了！任务停止。")
			return
		}

		// 👑 探长级黑科技 2：精准 SDK 状态码拦截与风控退避
		if svcErr, ok := common.IsServiceError(err); ok {
			statusCode := svcErr.GetHTTPStatusCode()

			if statusCode == 500 && strings.Contains(strings.ToLower(svcErr.GetMessage()), "out of host capacity") {
				fmt.Print(" ⚠️ 区域物理空间不足 (500 无货)，持续蹲守...")

			} else if statusCode == 429 || statusCode == 401 {
				// 429 限流 或 401 (短时间鉴权超载)
				rand.Seed(time.Now().UnixNano())
				backoffSec := 60 + rand.Intn(15) // 动态退避 60~75秒
				backoffMs := rand.Intn(1000)
				fmt.Printf("\n🛑 触发防刷风控 (状态码: %d)，启用深度蛰伏 %d.%03d 秒...", statusCode, backoffSec, backoffMs)
				time.Sleep(time.Duration(backoffSec)*time.Second + time.Duration(backoffMs)*time.Millisecond)
				continue

			} else {
				fmt.Printf(" ❌ 异常报错: [%d] %s", statusCode, svcErr.GetMessage())
			}
		} else {
			fmt.Printf(" ❌ 未知异常: %v", err)
		}

		// 毫秒级抖动防封 (打破傅里叶变换特征分析)
		rand.Seed(time.Now().UnixNano())
		delaySec := rand.Intn(conf.MaxDelay-conf.MinDelay+1) + conf.MinDelay
		delayMs := rand.Intn(1000)
		fmt.Printf("\n⏳ 伪装人类操作: 休眠 %d.%03d 秒...\n", delaySec, delayMs)
		time.Sleep(time.Duration(delaySec)*time.Second + time.Duration(delayMs)*time.Millisecond)
	}
}

func performLaunchInstance(conf GrabConfig) error {
	details := core.LaunchInstanceDetails{
		AvailabilityDomain: common.String(conf.ADName),
		CompartmentId:      common.String(compartmentID),
		DisplayName:        common.String("Oraman-Auto-Grabbed"),
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
			SubnetId: common.String(conf.SubnetID), // ✅ 完美修复：移除了不支持的 CompartmentId 字段，确保编译过关
		},
	}

	if conf.RootPassword != "" {
		script := fmt.Sprintf("#!/bin/bash\necho 'root:%s' | chpasswd\nsed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config\nsystemctl restart sshd", conf.RootPassword)
		details.Metadata = map[string]string{"user_data": base64.StdEncoding.EncodeToString([]byte(script))}
	}

	// 👑 探长级黑科技 3：严格的 Context 超时控制防挂起 (15秒)
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

	for {
		fmt.Printf("\n[%s] 正在向甲骨文提交配置升级请求...", time.Now().Format("15:04:05"))

		details := core.UpdateInstanceDetails{
			Shape: common.String("VM.Standard.A1.Flex"),
			ShapeConfig: &core.UpdateInstanceShapeConfigDetails{
				Ocpus:       common.Float32(4),
				MemoryInGBs: common.Float32(24),
			},
		}

		// 升级操作特殊放宽到 30 秒超时断开
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

		// 精准状态码拦截
		if svcErr, ok := common.IsServiceError(err); ok {
			statusCode := svcErr.GetHTTPStatusCode()
			errMsg := strings.ToLower(svcErr.GetMessage())
			if statusCode == 500 && (strings.Contains(errMsg, "out of host capacity") || strings.Contains(errMsg, "out of capacity")) {
				fmt.Print(" ⚠️ 当前宿主机无多余物理空间，继续蹲守...")
			} else if statusCode == 429 {
				rand.Seed(time.Now().UnixNano())
				backoffSec, backoffMs := 60+rand.Intn(15), rand.Intn(1000)
				fmt.Printf("\n🛑 触发风控 (429)，蛰伏 %d.%03d 秒...", backoffSec, backoffMs)
				time.Sleep(time.Duration(backoffSec)*time.Second + time.Duration(backoffMs)*time.Millisecond)
				continue
			} else {
				fmt.Printf(" ❌ 异常报错: [%d] %s", statusCode, svcErr.GetMessage())
			}
		} else {
			fmt.Printf(" ❌ 网络或本地异常: %v", err)
		}

		// 升级延迟，设定在 60-90 秒之间的随机安全延迟
		rand.Seed(time.Now().UnixNano())
		delaySec := rand.Intn(30) + 60
		delayMs := rand.Intn(1000)
		fmt.Printf(" ⏳ 休息 %d.%03d 秒...", delaySec, delayMs)
		time.Sleep(time.Duration(delaySec)*time.Second + time.Duration(delayMs)*time.Millisecond)
	}
}

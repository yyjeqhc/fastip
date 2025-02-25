use clap::Parser;
use clap::Subcommand;
use futures::future::join;
use futures::future::join_all;
use rand::random;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use surge_ping::{Client, Config, ICMP, IcmpPacket, PingIdentifier, PingSequence};
use tokio::time;
use tokio::time::{Duration, Instant};
use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
};
use std::fs::File;
use std::io::Write;
use std::cmp::{Eq,PartialEq};
#[derive(Parser, Debug)]
#[clap(
    name = "fastip",
    about = "A tool for concurrent resolution of multiple domains across multiple DNS servers, retrieving the fastest-resolved IP.",
    version = "0.1.0"
)]
struct Cli {
    /// Path to config file (YAML format)
    #[clap(short, long)]
    config: Option<PathBuf>,

    /// DNS servers to use (e.g. 8.8.8.8;[2620:fe::fe]) port is optional
    #[clap(short = 's', long = "server", value_name = "DNS_SERVER")]
    dns_servers: Vec<String>,

    /// Domains to resolve with optional record type (e.g. example.com:A)
    #[clap(short = 'd', long = "domain", value_name = "DOMAIN[:TYPE]")]
    domains: Vec<String>,

    /// Show verbose output
    #[clap(short, long)]
    verbose: bool,

    /// Subcommands
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 测试指定的dns服务器是否连通
    /// 可以使用-c 配置文件指定多个dns服务器
    Test {
        /// 指定的 DNS 服务器列表
        #[clap(short = 's', long = "server", value_name = "DNS_SERVER")]
        dns_servers: Vec<String>,

        /// 目标域名（默认为 baidu.com）
        #[clap(short = 'd',long = "domain",value_name = "DOMAIN",default_value = "baidu.com")]
        domain: String,
    },
    /// 从命令行状态的dns服务器配置解析成配置文件
    /// 支持从文件状态解析进去，文件内容为一行一行的命令行状态的dns服务器配置
    Gendns {
        /// 生成的配置文件路径
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// DNS servers to use (e.g. 8.8.8.8)
        #[clap(short = 's', long = "server", value_name = "DNS_SERVER")]
        dns_servers: Vec<String>,
    },
    /// 从命令行状态的域名配置解析成配置文件
    /// 支持从文件状态解析进去，文件内容为一行一行的命令行状态的域名配置 
    Genym {
        /// 生成的配置文件路径
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// domains to use (e.g. example.com)
        #[clap(short = 'd', long = "domains", value_name = "DOMAINS")]
        domains: Vec<String>,
    },
    /// Ping an address 5 times， and print output message（interval 1s）
    Ping {
        /// 目标IP（默认为 127.0.0.1）
        #[clap(short = 'd',long = "domain",value_name = "DOMAIN",default_value = "127.0.0.1")]
        domain: String,
    },
    /// 命令行指定dns服务器和域名，进行解析
    Lookup {
        #[clap(short = 's',long = "server",value_name = "DNS_SERVER",default_value = "8.8.8.8")]
        dns_servers: String,

        /// 目标域名（默认为 baidu.com）
        #[clap(short = 'd',long = "domain",value_name = "DOMAIN",default_value = "baidu.com")]
        domain: String,
    },
    /// 另一个子命令示例
    Another {
        #[clap(short, long)]
        flag: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolConfig {
    #[serde(rename = "dns_servers")]
    pub dns_servers: Vec<DnsServerConfig>,

    #[serde(rename = "domains")]
    pub domains: Vec<DomainConfig>,
}

#[derive(Debug, Serialize, Deserialize,Eq,PartialEq,Hash)]
pub struct DnsServerConfig {
    #[serde(rename = "address")]
    pub address: IpAddr,

    #[serde(rename = "port", default = "default_port")]
    pub port: u16,

    #[serde(rename = "protocol", default = "default_protocol")]
    pub protocol: DnsProtocol,
}

impl DnsServerConfig {
    fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}
#[derive(Debug, Serialize, Deserialize,Eq,PartialEq)]
pub struct DomainConfig {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "record_type", default = "default_record_type")]
    pub record_type: DnsRecordType,

    #[serde(rename = "enabled", default = "default_enabled")]
    pub enabled: bool,
    #[serde(skip)]
    pub v4: HashSet<IpAddr>,
    #[serde(skip)]
    pub v6: HashSet<IpAddr>,
    #[serde(skip)]
    pub fastest_v4: Option<IpAddr>,
    #[serde(skip)]
    pub fastest_v6: Option<IpAddr>,
}

#[derive(Debug, Serialize, Deserialize,Eq,PartialEq,Hash)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
}

#[derive(Debug, Serialize, Deserialize,Eq,PartialEq,Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    AAAA,
    TOTAL,
    MX,
    TXT,
    CNAME,
}

// 默认值处理函数
fn default_port() -> u16 {
    53
}
fn default_protocol() -> DnsProtocol {
    DnsProtocol::Udp
}
fn default_record_type() -> DnsRecordType {
    DnsRecordType::A
}
fn default_enabled() -> bool {
    true
}

// Ping an address 5 times， and print output message（interval 1s）
//返回给定IP的平均ping时间
async fn ping(client: Client, addr: IpAddr) -> f64 {
    let payload = [0; 56];
    let mut pinger = client.pinger(addr, PingIdentifier(random())).await;
    pinger.timeout(Duration::from_millis(200));
    let mut interval = time::interval(Duration::from_millis(200));

    let mut times = Vec::new();
    for idx in 0..4 {
        interval.tick().await;
        match pinger.ping(PingSequence(idx), &payload).await {
            Ok((IcmpPacket::V4(packet), dur)) => {
                // println!(
                //     "No.{}: {} bytes from {}: icmp_seq={} ttl={:?} time={:0.2?}",
                //     idx,
                //     packet.get_size(),
                //     packet.get_source(),
                //     packet.get_sequence(),
                //     packet.get_ttl(),
                //     dur
                // );
                times.push(dur.as_secs_f64());
            }
            Ok((IcmpPacket::V6(packet), dur)) => {
                // println!(
                //     "No.{}: {} bytes from {}: icmp_seq={} ttl={:?} time={:0.2?}",
                //     idx,
                //     packet.get_size(),
                //     packet.get_source(),
                //     packet.get_sequence(),
                //     packet.get_max_hop_limit(),
                //     dur
                // );
                times.push(dur.as_secs_f64());
            }
            Err(e) => {
                // println!("No.{}: {} ping {}", idx, pinger.host, e);
                times.push(1.0);
            }
        };
    }
    // 计算平均时间
    let average_time: f64 = times.iter().sum::<f64>() / times.len() as f64;
    // println!(
    //     "[+] {:?} Average ping time: {:0.2?} ms",
    //     addr,
    //     average_time * 1000.0
    // );

    average_time
}

//ping子命令使用
async fn ping_with_print(client: Client, addr: IpAddr) -> f64 {
    let payload = [0; 56];
    let mut pinger = client.pinger(addr, PingIdentifier(random())).await;
    pinger.timeout(Duration::from_millis(200));
    let mut interval = time::interval(Duration::from_millis(200));

    let mut times = Vec::new();
    for idx in 0..4 {
        interval.tick().await;
        match pinger.ping(PingSequence(idx), &payload).await {
            Ok((IcmpPacket::V4(packet), dur)) => {
                println!(
                    "No.{}: {} bytes from {}: icmp_seq={} ttl={:?} time={:0.2?}",
                    idx,
                    packet.get_size(),
                    packet.get_source(),
                    packet.get_sequence(),
                    packet.get_ttl(),
                    dur
                );
                times.push(dur.as_secs_f64());
            }
            Ok((IcmpPacket::V6(packet), dur)) => {
                println!(
                    "No.{}: {} bytes from {}: icmp_seq={} ttl={:?} time={:0.2?}",
                    idx,
                    packet.get_size(),
                    packet.get_source(),
                    packet.get_sequence(),
                    packet.get_max_hop_limit(),
                    dur
                );
                times.push(dur.as_secs_f64());
            }
            Err(e) => {
                println!("No.{}: {} ping {}", idx, pinger.host, e);
                times.push(1.0);
            }
        };
    }
    // 计算平均时间
    let average_time: f64 = times.iter().sum::<f64>() / times.len() as f64;
    println!(
        "[+] {:?} Average ping time: {:0.2?} ms",
        addr,
        average_time * 1000.0
    );

    average_time
}

fn load_config_yaml() -> ToolConfig {
    let config_content = fs::read_to_string("config.yml").expect("Unable to read config file");
    let config: ToolConfig =
        serde_yaml::from_str(&config_content).expect("Unable to parse config file");
    config
}

fn load_config(path: &PathBuf) -> Result<ToolConfig, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    Ok(serde_yaml::from_reader(file)?)
}

fn default_config() -> ToolConfig {
    ToolConfig {
        dns_servers: vec![DnsServerConfig {
            address: "8.8.8.8".parse().unwrap(),
            port: 53,
            protocol: DnsProtocol::Udp,
        }],
        domains: vec![],
    }
}

fn load_or_parse(cli: &Cli) -> Result<ToolConfig, Box<dyn std::error::Error>> {
    // 加载或创建默认配置
    let mut config = if let Some(config_path) = &cli.config {
        load_config(config_path)?
    } else {
        default_config()
    };

    // 合并命令行参数
    if !cli.dns_servers.is_empty() {
        config.dns_servers = cli
            .dns_servers
            .iter()
            .map(|s| parse_dns_server(s))
            .collect::<Result<_, _>>()?;
    }

    if !cli.domains.is_empty() {
        config.domains = cli
            .domains
            .iter()
            .map(|s| parse_domain(s))
            .collect::<Result<_, _>>()?;
    }
    Ok(config)
}


//对给定配置对象，使用所有 DNS 服务器并发解析所有域名，并保存解析结果，修改配置对象
async fn resolve_domain(config: &mut ToolConfig) -> Result<(), Box<dyn std::error::Error>> {
    // 创建自定义解析器配置
    let mut resolver_config = ResolverConfig::new();

    for dns_server in config.dns_servers.iter() {
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: dns_server.to_socket_addr(),
            protocol: Protocol::Udp, // 使用 UDP 协议
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
    }

    // 创建解析器选项（使用默认值）
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.timeout = Duration::from_secs(1); // 自定义超时时间
    resolver_opts.num_concurrent_reqs = 20;

    // 初始化异步解析器
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

    let start = Instant::now(); // 记录起始时间

    // 将 domains 的所有权移出 config
    let domains = std::mem::take(&mut config.domains);

    // 创建一个任务列表，用于存储每个域名的解析任务
    let mut tasks: Vec<_> = Vec::new();

    for mut domain in domains {
        if domain.enabled {
            let resolver = resolver.clone();
            let domain_name = domain.name.clone();
            // let record_type = domain.record_type.clone();

            // 为每个域名创建一个异步任务
            let task = tokio::spawn(async move {
                match domain.record_type {
                    DnsRecordType::A => {
                        if let Ok(ipv4_response) = resolver.ipv4_lookup(&domain_name).await {
                            for ip in ipv4_response.iter() {
                                domain.v4.insert(std::net::IpAddr::V4(ip.0));
                            }
                        }

                    }
                    DnsRecordType::AAAA => {
                        if let Ok(ipv6_response) = resolver.ipv6_lookup(&domain_name).await {
                            for ip in ipv6_response.iter() {
                                domain.v6.insert(std::net::IpAddr::V6(ip.0));
                            }
                        }
                    }
                    DnsRecordType::TOTAL => {
                        // 同时发起 IPv4 和 IPv6 查询
                        let ipv4_future = resolver.ipv4_lookup(&domain_name);
                        let ipv6_future = resolver.ipv6_lookup(&domain_name);

                        // 等待两者完成
                        let (ipv4_result, ipv6_result) = tokio::join!(ipv4_future, ipv6_future);

                        if let Ok(ipv4_response) = ipv4_result {
                            for ip in ipv4_response.iter() {
                                domain.v4.insert(std::net::IpAddr::V4(ip.0));
                            }
                        }
                        if let Ok(ipv6_response) = ipv6_result {
                            for ip in ipv6_response.iter() {
                                domain.v6.insert(std::net::IpAddr::V6(ip.0));
                            }
                        }
                    }
                    _ => {}
                }
                return domain;
            });

            tasks.push(task);
        }
    }

    // 等待所有任务完成
    let results = join_all(tasks).await;

    // 将 domains 的所有权移回 config
    config.domains = results.into_iter().map(|s|s.unwrap()).collect();

    println!("解析完成，耗时: {:?}", start.elapsed());
    Ok(())
}
async fn resolve_domain_old(config: &mut ToolConfig) -> Result<(), Box<dyn std::error::Error>> {
    // 创建自定义解析器配置
    let mut resolver_config = ResolverConfig::new();

    for dns_server in config.dns_servers.iter() {
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: dns_server.to_socket_addr(),
            protocol: Protocol::Udp, // 使用 UDP 协议
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
    }

    // 创建解析器选项（使用默认值）
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.timeout = Duration::from_secs(1); // 自定义超时时间
    resolver_opts.num_concurrent_reqs = 20;

    // 初始化异步解析器
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

    let start = Instant::now(); // 记录起始时间
    for domain in config.domains.iter_mut() {
        if domain.enabled {
            match domain.record_type {
                DnsRecordType::A => {
                    let ipv4_response = resolver.ipv4_lookup(&domain.name).await?;
                    for ip in ipv4_response.iter() {
                        // println!("{} {}", domain.name,ip);
                        domain.v4.insert(std::net::IpAddr::V4(ip.0));
                    }
                }
                DnsRecordType::AAAA => {
                    let ipv6_response = resolver.ipv6_lookup(&domain.name).await?;
                    for ip in ipv6_response.iter() {
                        // println!("{} {}", domain.name,ip);
                        domain.v6.insert(std::net::IpAddr::V6(ip.0));
                    }
                }
                DnsRecordType::TOTAL => {
                    // println!("{:?}",resolver.ipv4_lookup(&domain.name).await);
                    // println!("{:?}",resolver.ipv6_lookup(&domain.name).await);

                    // let ipv4_response = resolver
                    //     .ipv4_lookup(&domain.name)
                    //     .await
                    //     .unwrap_or(resolver.ipv4_lookup("localhost").await?);
                    // for ip in ipv4_response.iter() {
                    //     // println!("{} {}", domain.name,ip);
                    //     domain.v4.insert(std::net::IpAddr::V4(ip.0));
                    // }
                    // let ipv6_response = resolver
                    //     .ipv6_lookup(&domain.name)
                    //     .await
                    //     .unwrap_or(resolver.ipv6_lookup("localhost").await?);
                    // for ip in ipv6_response.iter() {
                    //     // println!("{} {}", domain.name,ip);
                    //     domain.v6.insert(std::net::IpAddr::V6(ip.0));
                    // }

                    let ipv4_response = resolver.ipv4_lookup(&domain.name);
                    let ipv6_response = resolver.ipv6_lookup(&domain.name);
                    let result = join(ipv4_response, ipv6_response).await;
                    // println!("{:?}",result);
                    match result {
                        (Ok(ipv4_response), Ok(ipv6_response)) => {
                            for ip in ipv4_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v4.insert(std::net::IpAddr::V4(ip.0));
                            }
                            for ip in ipv6_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v6.insert(std::net::IpAddr::V6(ip.0));
                            }
                        }
                        (Ok(ipv4_response), Err(_)) => {
                            for ip in ipv4_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v4.insert(std::net::IpAddr::V4(ip.0));
                            }
                            let v6_response = resolver.ipv6_lookup("localhost").await?;
                            for ip in v6_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v6.insert(std::net::IpAddr::V6(ip.0));
                            }
                        }
                        (Err(_), Ok(ipv6_response)) => {
                            for ip in ipv6_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v6.insert(std::net::IpAddr::V6(ip.0));
                            }
                            let v4_response = resolver.ipv4_lookup("localhost").await?;
                            for ip in v4_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v4.insert(std::net::IpAddr::V4(ip.0));
                            }
                        }
                        (Err(_), Err(_)) => {
                            let v4_response = resolver.ipv4_lookup("localhost").await?;
                            for ip in v4_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v4.insert(std::net::IpAddr::V4(ip.0));
                            }
                            let v6_response = resolver.ipv6_lookup("localhost").await?;
                            for ip in v6_response.iter() {
                                // println!("{} {}", domain.name,ip);
                                domain.v6.insert(std::net::IpAddr::V6(ip.0));
                            }
                        }
                    }
                    println!("{:?}", domain.v4);
                    println!("{:?}", domain.v6);
                }
                _ => {}
            };
        }
    }
    let elapsed = start.elapsed(); // 计算经过的时间
    println!("Loop took {:?}", elapsed);
    Ok(())
}

//检查dns服务器是否正常访问
async fn check_server(dns_server: SocketAddr, domain: String) -> Option<()> {
    let start = Instant::now(); // 记录起始时间

    // 创建解析器选项（使用默认值）
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.timeout = Duration::from_secs(1); // 自定义超时时间
    let mut resolver_config = ResolverConfig::new();
    resolver_config.add_name_server(NameServerConfig {
        socket_addr: dns_server,
        protocol: Protocol::Udp, // 使用 UDP 协议
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);
    let ipv4_response = resolver.ipv4_lookup(domain.clone());
    let ipv6_response = resolver.ipv6_lookup(domain);
    let result = join(ipv4_response, ipv6_response).await;
    match result {
        (Ok(_), Ok(_)) => {
            return Some(());
        }
        (Ok(_), Err(_)) => {
            let elapsed = start.elapsed(); // 计算经过的时间
            println!("v6 fail Loop took {:?}", elapsed);
            return Some(());
        }
        (Err(_), Ok(_)) => {
            let elapsed = start.elapsed(); // 计算经过的时间
            println!("v4 fail Loop took {:?}", elapsed);
            return Some(());
        }
        (Err(_), Err(_)) => {
            let elapsed = start.elapsed(); // 计算经过的时间
            println!("both fail Loop took {:?}", elapsed);
            return None;
        }
    }
}

fn save_config_as_yaml<P>(config: &ToolConfig, path: P)
where
    P: AsRef<Path>,
{
    // 将 Config 序列化为 YAML 字符串
    let yaml_string = serde_yaml::to_string(config).expect("Failed to serialize config");

    // 将 YAML 字符串写入文件
    fs::write(path, yaml_string).expect("Unable to write config file");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Test {
            dns_servers,
            domain,
        }) => {
            // println!("测试 DNS 服务器: {:?}", dns_servers);
            println!("解析的目标域名: {}", domain);

            let mut config = if let Some(config_path) = &cli.config {
                load_config(config_path)?
            } else {
                default_config()
            };
            // 合并命令行参数
            if !dns_servers.is_empty() {
                let tmp_dns_servers = dns_servers
                    .iter()
                    .map(|s| parse_dns_server(s))
                    .collect::<Result<_, _>>()?;
                if config.dns_servers.is_empty() {
                    config.dns_servers = tmp_dns_servers;
                } else {
                    // 将两个 Vec 合并到一个 HashSet 中
                    let s: HashSet<_> = tmp_dns_servers.into_iter().chain(config.dns_servers.into_iter()).collect();

                    config.dns_servers = s.into_iter().collect();
                }
            }

            //如果命令行指定了域名，就忽略配置文件的域名
            if !domain.is_empty() {
                config.domains = vec![parse_domain(domain)?];
            }
            // println!("{:?}", config);
            // 验证配置
            if config.dns_servers.is_empty() {
                return Err("At least one DNS server required".into());
            }

            if config.domains.is_empty() {
                return Err("At least one domain required".into());
            }
            // resolve_domain(&mut config).await;
            let mut tasks = Vec::new();
            for dns_server in config.dns_servers.iter() {
                tasks.push(tokio::spawn(check_server(
                    dns_server.to_socket_addr(),
                    config.domains[0].name.clone(),
                )))
            }
            let results = join_all(tasks).await;

            let results = results.into_iter().map(|x| x.unwrap()).collect::<Vec<_>>();

            // let dns_servers = vec![];
            // for tmp in config.dns_servers.iter().zip(results.iter()) {
            //     match tmp {
            //         (dns_server,Some(_)) => {
            //             println!("{} success",dns_server.to_socket_addr());
            //         },
            //         (dns_server,None) => {
            //             println!("{} fail",dns_server.to_socket_addr());
            //         }
            //     }
            // }
            // let r:Vec<_> = config.dns_servers.iter_mut().zip(results.iter()).filter(|(dns_server,result)| {
            //     match result {
            //         Some(_) => {
            //             println!("{} success",dns_server.to_socket_addr());
            //             true
            //         },
            //         None => {
            //             println!("{} fail",dns_server.to_socket_addr());
            //             false
            //         }
            //     }
            // }).collect();
            
            //保存能成功解析到的dns服务器到test.yml
            let r: Vec<_> = config
                .dns_servers
                .into_iter()
                .zip(results.iter())
                .filter_map(|(dns_server, result)| match result {
                    Some(_) => {
                        println!("{} success", dns_server.to_socket_addr());
                        Some(dns_server)
                    }
                    None => {
                        println!("{} fail", dns_server.to_socket_addr());
                        None
                    }
                })
                .collect();
            let config = ToolConfig {
                dns_servers: r,
                domains: vec![],
            };

            save_config_as_yaml(&config, "test.yml");
            return Ok(());
        }
        Some(Commands::Gendns {
            config,
            dns_servers,
        }) => {
            // 加载或创建默认配置
            fn load_dns_servers_from_file(path: &Path) -> io::Result<Vec<String>> {
                let content = fs::read_to_string(path)?;
                Ok(content.lines().map(String::from).collect())
            }

            let config_dns_servers = if let Some(config_path) = &config {
                let mut file_dns_servers = load_dns_servers_from_file(config_path)?;
                file_dns_servers.sort_unstable(); // 预排序方便去重
                file_dns_servers.dedup(); // 去重
                file_dns_servers
            } else {
                Vec::new()
            };
            // 合并命令行参数
            if !dns_servers.is_empty() {
                let mut all_dns_servers: HashSet<_> = config_dns_servers.into_iter().collect();
                for server in dns_servers {
                    all_dns_servers.insert(server.clone());
                }
                // cli.dns_servers = all_dns_servers.into_iter().collect();
                // println!("{:?}",all_dns_servers);
                let config: ToolConfig = ToolConfig {
                    dns_servers: all_dns_servers
                        .into_iter()
                        .map(|s| parse_dns_server(&s))
                        .collect::<Result<_, _>>()?,
                    domains: vec![],
                };
                save_config_as_yaml(&config, "generate_servers.yml");
                println!("配置文件已生成");
            } else {
                // println!("{:?}",config_dns_servers);
                let config: ToolConfig = ToolConfig {
                    dns_servers: config_dns_servers
                        .into_iter()
                        .map(|s| parse_dns_server(&s))
                        .collect::<Result<_, _>>()?,
                    domains: vec![],
                };
                save_config_as_yaml(&config, "generate_servers.yml");
                println!("配置文件已生成");
            }

            return Ok(());
        }
        Some(Commands::Genym {
            config,
            domains,
        }) => {
            // 加载或创建默认配置
            fn load_dns_servers_from_file(path: &Path) -> io::Result<Vec<String>> {
                let content = fs::read_to_string(path)?;
                Ok(content.lines().map(String::from).collect())
            }

            let config_dns_servers = if let Some(config_path) = &config {
                let mut file_dns_servers = load_dns_servers_from_file(config_path)?;
                file_dns_servers.sort_unstable(); // 预排序方便去重
                file_dns_servers.dedup(); // 去重
                file_dns_servers
            } else {
                Vec::new()
            };
            // println!("{:?}",config_dns_servers);
            // 合并命令行参数
            if !domains.is_empty() {
                let mut all_dns_servers: HashSet<_> = config_dns_servers.into_iter().collect();
                for server in domains {
                    all_dns_servers.insert(server.clone());
                }
                // cli.dns_servers = all_dns_servers.into_iter().collect();
                // println!("{:?}",all_dns_servers);
                let config: ToolConfig = ToolConfig {
                    domains: all_dns_servers
                        .into_iter()
                        .map(|s| parse_domain(&s))
                        .collect::<Result<_, _>>()?,
                    dns_servers: vec![],
                };
                save_config_as_yaml(&config, "generate_domains.yml");
                println!("配置文件已生成");
            } else {
                // println!("{:?}",config_dns_servers);
                let config: ToolConfig = ToolConfig {
                    domains: config_dns_servers
                        .into_iter()
                        .map(|s| parse_domain(&s))
                        .collect::<Result<_, _>>()?,
                    dns_servers: vec![],
                };
                save_config_as_yaml(&config, "generate_domains.yml");
                println!("配置文件已生成");
            }

            return Ok(());
        }
        
        Some(Commands::Ping { domain }) => {
            println!("执行 Ping 子命令");
            async fn lookup(domain: &str) -> IpAddr {
                let config = ToolConfig {
                    dns_servers: vec![parse_dns_server("8.8.8.8").unwrap()],//默认指定了8.8.8.8，未必可以正常解析
                    domains: vec![parse_domain(domain).unwrap()],
                };
                let mut resolver_config = ResolverConfig::new();

                for dns_server in config.dns_servers.iter() {
                    resolver_config.add_name_server(NameServerConfig {
                        socket_addr: dns_server.to_socket_addr(),
                        protocol: Protocol::Udp, // 使用 UDP 协议
                        tls_dns_name: None,
                        trust_negative_responses: false,
                        bind_addr: None,
                    });
                }

                // 创建解析器选项（使用默认值）
                let mut resolver_opts = ResolverOpts::default();
                resolver_opts.timeout = Duration::from_secs(1); // 自定义超时时间
                // let resolver_opts = ResolverOpts {
                //     timeout: Duration::from_secs(1), // 自定义超时时间
                //     ..ResolverOpts::default()        // 其余字段使用默认值
                // };

                // 初始化异步解析器
                let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);
                let ip = resolver.lookup_ip(config.domains[0].name.clone()).await.unwrap_or(resolver.lookup_ip("localhost").await.unwrap()).iter().next().unwrap();
                return ip;
            }
            match domain.parse().unwrap_or(lookup(domain).await) {
                IpAddr::V4(v4) => {
                    let client_v4 = Client::new(&Config::default())?;
                    ping_with_print(client_v4, std::net::IpAddr::V4(v4)).await;
                }
                IpAddr::V6(v6) => {
                    let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build())?;
                    ping_with_print(client_v6, std::net::IpAddr::V6(v6)).await;
                }
            }

            return Ok(());
        }
        Some(Commands::Lookup {
            dns_servers,
            domain,
        }) => {
            let mut config = ToolConfig {
                dns_servers: vec![parse_dns_server(dns_servers)?],
                domains: vec![parse_domain(domain)?],
            };
            let _ = resolve_domain(&mut config).await;
            println!("lookup finish");
            return Ok(());
        }
        Some(Commands::Another { flag }) => {
            println!("执行 Another 子命令, flag: {}", flag);
            return Ok(());
        }

        None => {
            println!("执行主程序逻辑...");
            // 这里放原来的主程序逻辑
        }
    }

    let mut config = load_or_parse(&cli)?;

    // 验证配置
    if config.dns_servers.is_empty() {
        return Err("At least one DNS server required".into());
    }

    if config.domains.is_empty() {
        return Err("At least one domain required".into());
    }

    // let mut config = load_config_yaml();
    // 指定目标域名和 DNS 服务器

    let _ = resolve_domain(&mut config).await;
    println!("resolve_domain finish");
    let mut file = File::create("hosts.txt")?;

    let start = Instant::now(); // 记录起始时间

    let _ = find_fastest_ip_new(&mut config).await;
    println!("ping完成，耗时: {:?}", start.elapsed());

    for domain in config.domains.iter_mut() {
        if domain.enabled {
            // println!("{} {:?}", domain.name, domain.v4);
            // println!("{} {:?}", domain.name, domain.v6);
            // let _ = find_fastest_ip(domain).await;
            // println!("{:?}", domain.fastest_v4);
            // println!("{:?}", domain.fastest_v6);

            //移至下面，上面的find需要优化
            // match domain.fastest_v4 {
            //     Some(ip) => {
            //         let output = format!("{} {}", ip, domain.name);
            //         // 写入文件
            //         writeln!(file, "{}", output)?;
            //     }
            //     None =>{}
            // }
            // match domain.fastest_v6 {
            //     Some(ip) => {
            //         let output = format!("{} {}", ip, domain.name);
            //         // 写入文件
            //         writeln!(file, "{}", output)?;
            //     }
            //     None => {}
            // }
        }
    }

    for domain in config.domains.iter() {
        if domain.enabled {
            match domain.fastest_v4 {
                Some(ip) => {
                    let output = format!("{} {}", ip, domain.name);
                    writeln!(file, "{}", output)?;
                }
                None =>{}
            }
            match domain.fastest_v6 {
                Some(ip) => {
                    let output = format!("{} {}", ip, domain.name);
                    writeln!(file, "{}", output)?;
                }
                None => {}
            }
        }
    }
    Ok(())
}

async fn find_fastest_ip_new(config: &mut ToolConfig) -> Result<(), Box<dyn std::error::Error>> {
    // 过滤掉本地回环地址
    for domain in config.domains.iter_mut() {
        domain
            .v4
            .retain(|&ip| ip != IpAddr::V4("127.0.0.1".parse().unwrap()));
        domain
            .v6
            .retain(|&ip| ip != IpAddr::V6("::1".parse().unwrap()));
    }

    let domains_old = std::mem::take(&mut config.domains);
    // 使用 Arc<Mutex<T>> 共享 domains
    // let domains = Arc::new(Mutex::new(domains_old));

    // 创建一个任务列表，用于存储每个域名的 Ping 任务
    let mut tasks: Vec<_> = Vec::new();

    for mut domain in domains_old.into_iter() {
        if domain.enabled {

            // 为每个域名创建一个异步任务
            let task = tokio::spawn(async move {

                // 处理 IPv4 地址
                if !domain.v4.is_empty() {
                    let client_v4 = Client::new(&Config::default()).unwrap();
                    let mut tasks_v4 = Vec::new();

                    // 为每个 IPv4 地址创建一个 Ping 任务
                    for ip in domain.v4.iter() {
                        tasks_v4.push(tokio::spawn(ping(client_v4.clone(), *ip)));
                    }

                    // 等待所有 IPv4 Ping 任务完成
                    let results_v4 = join_all(tasks_v4).await;

                    let mut fastest_ip_v4 = None;
                    let mut min_ping_time_v4 = f64::MAX;

                    // 计算最快的 IPv4 地址
                    for (ip, result) in domain.v4.iter().zip(results_v4) {
                        match result {
                            Ok(avg_time) => {
                                if avg_time < min_ping_time_v4 {
                                    fastest_ip_v4 = Some(*ip);
                                    min_ping_time_v4 = avg_time;
                                }
                            }
                            Err(e) => {
                                eprintln!("Error pinging {}: {}", ip, e);
                            }
                        }
                    }

                    domain.fastest_v4 = fastest_ip_v4;
                    println!(
                        "IPv4 - Domain: {:?}, Fastest IP: {:?}, Ping Time: {:0.2} ms",
                        domain.name,
                        fastest_ip_v4,
                        min_ping_time_v4 * 1000.0
                    );
                }

                // 处理 IPv6 地址
                if !domain.v6.is_empty() {
                    let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build()).unwrap();
                    let mut tasks_v6 = Vec::new();

                    // 为每个 IPv6 地址创建一个 Ping 任务
                    for ip in domain.v6.iter() {
                        tasks_v6.push(tokio::spawn(ping(client_v6.clone(), *ip)));
                    }

                    // 等待所有 IPv6 Ping 任务完成
                    let results_v6 = join_all(tasks_v6).await;

                    let mut fastest_ip_v6 = None;
                    let mut min_ping_time_v6 = f64::MAX;

                    // 计算最快的 IPv6 地址
                    for (ip, result) in domain.v6.iter().zip(results_v6) {
                        match result {
                            Ok(avg_time) => {
                                if avg_time < min_ping_time_v6 {
                                    fastest_ip_v6 = Some(*ip);
                                    min_ping_time_v6 = avg_time;
                                }
                            }
                            Err(e) => {
                                eprintln!("Error pinging {}: {}", ip, e);
                            }
                        }
                    }

                    domain.fastest_v6 = fastest_ip_v6;
                    println!(
                        "IPv6 - Domain: {:?}, Fastest IP: {:?}, Ping Time: {:0.2} ms",
                        domain.name,
                        fastest_ip_v6,
                        min_ping_time_v6 * 1000.0
                    );
                }
                return domain;
            });

            tasks.push(task);
        }
    }

    // 等待所有域名任务完成
    let results = join_all(tasks).await;
    config.domains = results.into_iter().map(|s|s.unwrap()).collect();
    Ok(())
}
async fn find_fastest_ip(domain: &mut DomainConfig) -> Result<(), Box<dyn std::error::Error>> {
    domain
        .v4
        .retain(|&ip| ip != IpAddr::V4("127.0.0.1".parse().unwrap()));
    domain
        .v6
        .retain(|&ip| ip != IpAddr::V6("::1".parse().unwrap()));
    if domain.v4.len() > 0 {
        let mut tasks = Vec::new();

        let client_v4 = Client::new(&Config::default())?;
        // 遍历 v4 和 v6 地址，创建 ping 任务
        for ip in domain.v4.iter() {
            tasks.push(tokio::spawn(ping(client_v4.clone(), *ip)))
        }
        let results = join_all(tasks).await;
        // println!("{:?}",results);
        let mut fastest_ip = None;
        let mut min_ping_time = f64::MAX;

        for (ip, result) in domain.v4.iter().zip(results) {
            match result {
                Ok(avg_time) => {
                    // println!(
                    //     "IP: {:?}, Average Ping Time: {:0.2?} ms",
                    //     ip,
                    //     avg_time * 1000.0
                    // );
                    if avg_time < min_ping_time {
                        fastest_ip = Some(*ip);
                        min_ping_time = avg_time;
                    }
                }
                Err(e) => {
                    eprintln!("Error pinging {}: {}", ip, e);
                }
            }
        }
        println!(
            "name {:?} {:?} {}ms",
            domain.name,
            fastest_ip,
            min_ping_time * 1000.0
        );

        domain.fastest_v4 = fastest_ip;
        // 等待所有任务完成
    }
    if domain.v6.len() > 0 {
        let mut tasks = Vec::new();

        let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build())?;
        // 遍历 v4 和 v6 地址，创建 ping 任务
        for ip in domain.v6.iter() {
            tasks.push(tokio::spawn(ping(client_v6.clone(), *ip)))
        }
        let results = join_all(tasks).await;
        // println!("{:?}",results);
        let mut fastest_ip = None;
        let mut min_ping_time = f64::MAX;

        for (ip, result) in domain.v6.iter().zip(results) {
            match result {
                Ok(avg_time) => {
                    // println!(
                    //     "IP: {:?}, Average Ping Time: {:0.2?} ms",
                    //     ip,
                    //     avg_time * 1000.0
                    // );
                    if avg_time < min_ping_time {
                        fastest_ip = Some(*ip);
                        min_ping_time = avg_time;
                    }
                }
                Err(e) => {
                    eprintln!("Error pinging {}: {}", ip, e);
                }
            }
        }
        println!(
            "name {:?} {:?} {}ms",
            domain.name,
            fastest_ip,
            min_ping_time * 1000.0
        );
        domain.fastest_v6 = fastest_ip;
        // 等待所有任务完成
    }

    Ok(())
}

fn parse_dns_server(s: &str) -> Result<DnsServerConfig, Box<dyn Error>> {
    // let (ip_str, port_str) = match s.rsplit_once(':') {
    //     Some((ip, port)) => (ip, port),
    //     None => (s, "53"), // 如果没有端口，使用默认端口 53
    // };

    // let address = ip_str.parse::<IpAddr>()?;
    // let port = port_str.parse::<u16>().unwrap_or(default_port());

    let (address_str, port_str) = if s.starts_with('[') {
        // IPv6 地址包含在方括号中
        let end_bracket_pos = s
            .find(']')
            .ok_or("Invalid IPv6 address: missing closing bracket")?;

        if end_bracket_pos == s.len() - 1 {
            // 只有 IPv6 地址，没有端口
            (s, "53")
        } else if s.len() > end_bracket_pos + 2 && s.as_bytes()[end_bracket_pos + 1] == b':' {
            // IPv6:port
            (&s[1..end_bracket_pos], &s[end_bracket_pos + 2..])
        } else {
            return Err("Invalid IPv6 address format".into());
        }
    } else {
        // IPv4 或 IPv4:port
        match s.rsplit_once(':') {
            Some((ip, port)) => (ip, port),
            None => (s, "53"), // 如果没有端口，使用默认端口 53
        }
    };

    let address = address_str
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()?; // 去掉方括号并解析IP地址
    let port = port_str.parse::<u16>().unwrap_or(default_port());

    // 这里可以设置默认协议，或者根据需要进行调整
    let protocol = default_protocol();

    Ok(DnsServerConfig {
        address,
        port,
        protocol,
    })
}

fn parse_domain(s: &str) -> Result<DomainConfig, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let (name, record_type) = (
        parts[0].to_string(),
        parts.get(1).map_or(DnsRecordType::TOTAL, |s| match *s {
            "A" => DnsRecordType::A,
            "AAAA" => DnsRecordType::AAAA,
            _ => DnsRecordType::TOTAL,
        }),
    );

    Ok(DomainConfig {
        name,
        enabled: true,
        record_type,
        v4: HashSet::new(),
        v6: HashSet::new(),
        fastest_v4: None,
        fastest_v6: None,
    })
}

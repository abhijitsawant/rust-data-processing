use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use chrono::Local;

const SYSLOG_DIR: &str = "./syslog";
const OUTPUT_DIR: &str = "./output";

#[derive(Serialize, Deserialize, Debug)]
struct Record {
    key: String,
    #[serde(rename = "source-ip")]
    source_ip: String,
    #[serde(rename = "destination-ip")]
    destination_ip: String,
    #[serde(rename = "packets-in")]
    packets_in: u64,
    #[serde(rename = "bytes-in")]
    bytes_in: u64,
    #[serde(rename = "packets-out")]
    packets_out: u64,
    #[serde(rename = "bytes-out")]
    bytes_out: u64,
    count: u64,
}

#[derive(Serialize, Debug)]
struct Metadata {
    startTime: u128,
    endTime: u128,
    elapsedTime: f64,
    totalConnections: u64,
    sessionClose: String,
    flows: usize,
    filesProcessed: Vec<String>,
    processingPerformance: HashMap<String, String>,
}

#[derive(Serialize, Debug)]
struct Payload {
    metadata: Metadata,
    data: HashMap<String, Record>,
}

fn generate_output_filename() -> String {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    format!("{}/FDB_DP_v11_{}.json", OUTPUT_DIR, timestamp)
}

fn process_syslog_files(start_time: u128) {
    let mut master_record: HashMap<String, Record> = HashMap::new();
    let mut connections: u64 = 0;
    let mut session_close: u64 = 0;
    let mut files_processed: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir(SYSLOG_DIR) {
        for entry in entries.flatten() {
            let filepath = entry.path();
            if filepath.is_file() {
                if let Ok(file) = File::open(&filepath) {
                    let reader = BufReader::new(file);
                    files_processed.push(filepath.display().to_string());

                    for line in reader.lines().flatten() {
                        connections += 1;
                        let parts: Vec<&str> = line.trim().split(',').collect();
                        if parts.len() < 13 {
                            continue;
                        }

                        let firewall_ip = parts[1];
                        let source_ip = parts[3];
                        let destination_ip = parts[4];
                        let destination_port = parts[5];
                        let protocol_id = parts[6];
                        let packets_in = parts[9];
                        let bytes_in = parts[10];
                        let packets_out = parts[11];
                        let bytes_out = parts[12];

                        if packets_in.is_empty() || bytes_in.is_empty() || packets_out.is_empty() || bytes_out.is_empty() {
                            continue;
                        }

                        let (Ok(packets_in), Ok(bytes_in), Ok(packets_out), Ok(bytes_out)) =
                            (packets_in.parse::<u64>(), bytes_in.parse::<u64>(),
                             packets_out.parse::<u64>(), bytes_out.parse::<u64>()) else {
                            continue;
                        };

                        session_close += 1;

                        let key = format!("{}_{}_{}_{}_{}", firewall_ip, source_ip, destination_ip, destination_port, protocol_id);

                        master_record.entry(key.clone())
                            .and_modify(|rec| {
                                rec.packets_in += packets_in;
                                rec.bytes_in += bytes_in;
                                rec.packets_out += packets_out;
                                rec.bytes_out += bytes_out;
                                rec.count += 1;
                            })
                            .or_insert(Record {
                                key,
                                source_ip: source_ip.to_string(),
                                destination_ip: destination_ip.to_string(),
                                packets_in,
                                bytes_in,
                                packets_out,
                                bytes_out,
                                count: 1,
                            });
                    }
                }
            }
        }
    }

    // Ensure output directory exists
    fs::create_dir_all(OUTPUT_DIR).unwrap();

    let end_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let elapsed_time = (end_time - start_time) as f64 / 1000.0;

    let mut perf = HashMap::new();
    perf.insert(
        "connectionsPerSecond".to_string(),
        format!("{:.2} connections/second", connections as f64 / elapsed_time),
    );

    let metadata = Metadata {
        startTime: start_time,
        endTime: end_time,
        elapsedTime: elapsed_time,
        totalConnections: connections,
        sessionClose: format!("{} ({:.2}% of total connections)", session_close, (session_close as f64 / connections as f64) * 100.0),
        flows: master_record.len(),
        filesProcessed: files_processed,
        processingPerformance: perf,
    };

    let payload = Payload {
        metadata,
        data: master_record,
    };

    let output_file = generate_output_filename();
    let out = File::create(&output_file).expect("Unable to create output file");
    serde_json::to_writer_pretty(out, &payload).expect("Unable to write JSON");

    println!("Master record written to {} with {} unique keys.", output_file, payload.data.len());
}

fn main() {
    let start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    process_syslog_files(start_time);
}

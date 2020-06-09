use clap::{App, Arg};
use colored::*;
use json;
use std::fs;
use std::io::prelude::*;
use std::process;

mod helpers;

fn main() {
    // parse command line arguments

    let args = App::new("JS Parse")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true),
        )
        .arg(Arg::with_name("verbose").short("v").long("verbose"))
        .get_matches();

    let input = args.value_of("input").unwrap();

    let domain = args.value_of("domain").unwrap();

    let output = args.is_present("output");

    let verbosity = args.is_present("verbose");

    // get a list of everything in the input directory
    let files = match fs::read_dir(input) {
        Ok(files) => files,
        Err(err) => {
            eprintln!("{} {}", "error:".bright_red().bold(), err);
            process::exit(-1);
        }
    };

    let mut subdomains: Vec<String> = Vec::with_capacity(0xfff);
    let mut endpoints: Vec<String> = Vec::with_capacity(0xfff);
    let mut parameter: Vec<String> = Vec::with_capacity(0xfff);
    let mut headers: Vec<String> = Vec::with_capacity(0xff);
    let mut api_keys: Vec<String> = Vec::with_capacity(0xff);

    // iterate over content of directory
    for file in files {
        let file = file.unwrap();

        // get metadata and check if it is a file
        let md = fs::metadata(file.path()).unwrap();

        if !md.is_file() {
            continue;
        }

        if verbosity {
            println!(
                "{} Scanning {}...",
                "info:".bright_blue().bold(),
                file.path().to_string_lossy()
            );
        }

        // read file content
        let content = match fs::read_to_string(file.path()) {
            Ok(content) => content,
            Err(err) => {
                eprintln!("{} {}", "error:".bright_red().bold(), err);
                continue;
            }
        };

        // find subdomains
        let subs: Vec<String> = helpers::find_subdomains(&domain, &content);

        // iterate over subs and check if it was not found already
        for sub in subs {
            if !subdomains.contains(&sub) {
                subdomains.push(sub);
            }
        }

        // find endpoints
        let endps: Vec<String> = helpers::find_endpoints(&domain, &content);

        // iterate over endps and check if it was not found already
        for endp in endps {
            if !endpoints.contains(&endp) {
                endpoints.push(endp);
            }
        }

        // find parameter
        let params: Vec<String> = helpers::find_parameter(&content);

        // iterate over params and check if it was not found already
        for param in params {
            if !parameter.contains(&param) {
                parameter.push(param);
            }
        }

        // find header
        let hs: Vec<String> = helpers::find_header(&content);

        // iterate over hs and check if it was not found already
        for h in hs {
            if !headers.contains(&h) {
                headers.push(h);
            }
        }

        // find api keys
        let keys: Vec<String> = helpers::find_api_keys(&content);

        // iterate over keys and check if it was not found already
        for key in keys {
            if !api_keys.contains(&key) {
                api_keys.push(key);
            }
        }
    }

    if verbosity {
        println!();
    }

    // verify that subdomains were found at all
    if subdomains.len() > 0 {
        println!("{}:", "Subdomains".bright_green().bold());

        for sub in &subdomains {
            println!("\t{}", sub);
        }
    } else {
        println!("{}", "No subdomains were found.".bright_red().bold());
    }

    // pretty printing
    println!();

    // verify that endpoints were found at all
    if endpoints.len() > 0 {
        println!("{}:", "Endpoints".bright_green().bold());

        for endpoint in &endpoints {
            println!("\t{}", endpoint);
        }
    } else {
        println!("{}", "No endpoints were found.".bright_red().bold());
    }

    // pretty printing
    println!();

    // verify that parameter were found at all
    if parameter.len() > 0 {
        println!("{}:", "Parameter".bright_green().bold());

        for param in &parameter {
            println!("\t{}", param);
        }
    } else {
        println!("{}", "No parameter were found.".bright_red().bold());
    }

    // pretty printing
    println!();

    // verify that header were found at all
    if headers.len() > 0 {
        println!("{}:", "Custom Headers".bright_green().bold());

        for header in &headers {
            println!("\t{}", header);
        }
    } else {
        println!("{}", "No custom headers were found.".bright_red().bold());
    }

    // pretty printing
    println!();

    if api_keys.len() > 0 {
        println!("{}:", "API Keys".bright_green().bold());

        for key in &api_keys {
            let values: Vec<&str> = key.split("|").collect();

            println!("\t{}: {}", values[0].bright_cyan().bold(), values[1]);
        }
    } else {
        println!("{}", "No API keys were found.".bright_red().bold());
    }

    // create output
    if output {
        //pretty printing
        println!();

        let output_file = args.value_of("output").unwrap();

        let mut output = json::JsonValue::new_object();

        output["subdomains"] = subdomains.into();
        output["endpoints"] = endpoints.into();
        output["parameter"] = parameter.into();
        output["headers"] = headers.into();

        for key in &api_keys {
            let values: Vec<&str> = key.split("|").collect();

            output["keys"][values[0]] = values[1].into();
        }

        let mut file = fs::File::create(output_file).unwrap();

        match file.write(output.dump().as_bytes()) {
            Ok(_ok) => println!(
                "{}: {} {}",
                "info".bright_blue().bold(),
                "Saved results in",
                output_file
            ),
            Err(err) => eprintln!("{} {}", "error:".bright_red().bold(), err),
        };
    }
}

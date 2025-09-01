#!/bin/env ruby
require 'nokogiri'
require 'optparse'

class DmarcReport
  def self.run
    dr = self.new
    dr.parse
    dr.dispatch
  end

  def self.usage
    abort('dmarc-report-cli.rb [-C] [-O summary|stream|sourceip|domain|from|json] [-d <domain>] <reports_directory>')
  end

  def initialize
    @opts = {}
    op = OptionParser.new
    op.on("-O FMT", "--output-format")
    op.on("-d DOMAIN", "--domain")
    op.on("-C", "--nocolor")
    op.parse!(ARGV, into: @opts)
    @dir = ARGV.shift
    DmarcReport.usage unless File.directory? @dir
    @reports = []
  end

  attr :reports

  def dispatch
    case @opts[:"output-format"]
    when "sourceip"
      source_ip
    when "stream"
      stream
    when "domain"
      domain_count
    when "from"
      domain_header_from
    when "json"
      json
    else
      summary
    end
  end

  def parse
    entities = Dir.children(@dir).sort_by {|i| i.split('!')[2].to_i }
    entities.each do |fn|
      begin
        xml = File.read(File.join(@dir, fn))
        doc = Nokogiri::XML(xml)
    
        org = doc.at_xpath("feedback/report_metadata/org_name").text
        date_begin = doc.at_xpath("feedback/report_metadata/date_range/begin").text
        date_end = doc.at_xpath("feedback/report_metadata/date_range/end").text
    
        policy = {}
        policy[:domain] = doc.at_xpath("feedback/policy_published/domain")&.text || ""
        policy[:adkim] = doc.at_xpath("feedback/policy_published/adkim")&.text || ""
        policy[:aspf] = doc.at_xpath("feedback/policy_published/aspf")&.text || ""
        policy[:p] = doc.at_xpath("feedback/policy_published/p")&.text || ""

        if @opts[:domain]
          next unless policy[:domain].downcase == @opts[:domain].downcase
        end

        records = []
        doc.xpath('feedback/record').each do |rx|
          r = {}
          r[:ip] = rx.at_xpath("row/source_ip").text
          r[:count] = rx.at_xpath("row/count").text.to_i
          r[:row] = {
            disp: rx.at_xpath("row/policy_evaluated/disposition").text,
            dkim: (rx.at_xpath("row/policy_evaluated/dkim").text&.downcase == "pass"),
            spf: (rx.at_xpath("row/policy_evaluated/spf").text&.downcase == "pass")
          }
          r[:id] = rx.xpath("identifiers").map {|ri| ri.at_xpath("header_from").text }
          r[:result] = {
            dkim: rx.xpath("auth_results/dkim").map {|ri|
              ({
                domain: ri.at_xpath("./domain").text,
                result: ri.at_xpath("./result").text
              })
            },
            spf: rx.xpath("auth_results/spf").map {|ri|
              {
                domain: ri.xpath("domain").text,
                result: ri.xpath("result").text
              }
            }
          }
          records.push r
        end
    
        data = {
          report_meta: {
            org:,
            date: {
              begin: Time.at(date_begin.to_i),
              end: Time.at(date_end.to_i)
            }
          },
          policy:,
          records:,
        }
        @reports.push data
      rescue
        $stderr.puts "Cannot recognize #{fn}"
      end
    end
  end

  def summary
    dkim = {pass:0, fail:0}
    spf = {pass:0, fail:0}
    dmarc = {pass:0, fail:0}
    ip_addr = {pass: Hash.new(0), fail: Hash.new(0)}
    volume_total = 0
    records_total = 0

    @reports.each do |report|
      report[:records].each do |record|
        dkim_passed = record[:row][:dkim]
        spf_passed = record[:row][:spf]
        dmarc_passed = dkim_passed | spf_passed
        num = record[:count]
        dkim[dkim_passed ? :pass : :fail] += num
        spf[spf_passed ? :pass : :fail] += num
        dmarc[dmarc_passed ? :pass : :fail] += num
        ip_addr[dmarc_passed ? :pass : :fail][record[:ip]] += num
        records_total += 1
        volume_total += num
      end
    end

    top_fail_ipaddr = ip_addr[:fail].keys.sort_by {|k| ip_addr[:fail][k] }.reverse[0, 10]

    printf "%12s #{@reports.length}\n", "Reports:"
    printf "%12s #{records_total}\n", "Records:"
    printf "%12s #{volume_total}\n", "Count:"
    printf "%12s #{color_grn("pass")} %d : #{color_red("fail")} %d - %s%% passed  \n", "SPF:", spf[:pass], spf[:fail], pass_pct_color(spf[:pass].to_f / volume_total * 100)
    printf "%12s #{color_grn("pass")} %d : #{color_red("fail")} %d - %s%% passed  \n", "DKIM:", dkim[:pass], dkim[:fail], pass_pct_color(dkim[:pass].to_f / volume_total * 100)
    printf "%12s #{color_grn("pass")} %d : #{color_red("fail")} %d - %s%% passed  \n", "DMARC:", dmarc[:pass], dmarc[:fail], pass_pct_color(dmarc[:pass].to_f / volume_total * 100)
    puts
    printf "%12s\n", "[IP ADDR]"
    printf "%12s %d\n", "passed:", ip_addr[:pass].length
    ip_addr[:pass].each do |k,v|
      printf "%12s %s (%d)\n", "", color_grn(k), v
    end
    printf "%12s %d\n", "failed:", ip_addr[:fail].length
    top_fail_ipaddr.each do |k|
      printf "%12s %s (%d)\n", "", color_red(k), ip_addr[:fail][k]
    end
  end

  def stream
    @reports.each do |report|
      org = sprintf "%16.16s", report[:report_meta][:org]
      report[:records].each do |record|
        dmarc_passed = record[:row][:spf] | record[:row][:dkim]
        printf "%s %24.24s %2s %2s %10s %d %s\n", (dmarc_passed ? color_grn(org) : color_red(org)), record[:id].join(","), (record[:row][:spf] ? color_grn("Sp") : color_red("Sf")), (record[:row][:dkim] ? color_grn("Dp") : color_red("Df")), color_disposition(record[:row][:disp]), record[:count], record[:ip]
      end
    end
  end

  def source_ip
    ip_addr = {pass: Hash.new(0), fail: Hash.new(0)}

    @reports.each do |report|
      report[:records].each do |record|
        dmarc_passed = record[:row][:spf] | record[:row][:dkim]
        num = record[:count]
        ip_addr[dmarc_passed ? :pass : :fail][record[:ip]] += num
      end
    end

    sorted_fail_ipaddr = ip_addr[:fail].keys.sort_by {|k| ip_addr[:fail][k] }.reverse

    sorted_fail_ipaddr.each do |k|
      puts "#{k} #{ip_addr[:fail][k]}"
    end
  end

  def domain_count
    domains = {}
    volume_total = 0
    @reports.each do |report|
      report[:records].each do |record|
        dmarc_passed = record[:row][:spf] | record[:row][:dkim]
        domain = report[:policy][:domain]
        domains[domain] ||= {pass: 0, fail:0}
        num = record[:count]
        domains[domain][(dmarc_passed ? :pass : :fail)] += num
        volume_total += num
      end
    end

    domains.each do |k,v|
      printf("%s %s %s %.2f%%\n", k, color_grn(v[:pass]), color_red(v[:fail]), (v[:pass].to_f / volume_total * 100))
    end
  end

  def domain_header_from
    domains = {}
    volume_total = 0
    @reports.each do |report|
      report[:records].each do |record|
        dmarc_passed = record[:row][:spf] | record[:row][:dkim]
        domain = report[:policy][:domain]
        domains[domain] ||= {}
        num = record[:count]
        header_from = record[:id]
        header_from.each do |hf|
          domains[domain][hf] ||= {pass: 0, fail: 0}
          domains[domain][hf][(dmarc_passed ? :pass : :fail)] += num
        end
        volume_total += num
      end
    end

    domains.each do |dk,dv|
      puts dk
      dv.each do |k,v|
        printf("%s %s %s %.2f%%\n", k, color_grn(v[:pass]), color_red(v[:fail]), (v[:pass].to_f / volume_total * 100))
      end
      puts
    end
  end

  def json
    require 'json'
    reports = Marshal.load Marshal.dump @reports
    reports.each do |i|
      i[:report_meta][:date] = {
        begin: i[:report_meta][:date][:begin].to_i,
        end: i[:report_meta][:date][:end].to_i
      }
    end

    puts JSON.pretty_unparse reports
  end

  def color_red str
    return str if @opts[:nocolor]
    "\e[31m#{str}\e[0m"
  end

  def color_mag str
    return str if @opts[:nocolor]
    "\e[35m#{str}\e[0m"
  end

  def color_yel str
    return str if @opts[:nocolor]
    "\e[33m#{str}\e[0m"
  end

  def color_grn str
    return str if @opts[:nocolor]
    "\e[32m#{str}\e[0m"
  end

  def color_blu str
    return str if @opts[:nocolor]
    "\e[36m#{str}\e[0m"
  end

  def pass_pct_color pct
    pctstr = sprintf "%.2f", pct
    case pct
    when 0...20
      color_red pctstr
    when 20...40
      color_mag pctstr
    when 40...60
      color_yel pctstr
    when 60...80
      color_grn pctstr
    else
      color_blu pctstr
    end
  end

  def color_disposition str
    case str.downcase
    when "reject"
      color_red str
    when "quarantine"
      color_yel str
    else
      str
    end
  end
end

DmarcReport.run
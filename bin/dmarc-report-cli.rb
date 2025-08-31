#!/bin/env ruby
require 'nokogiri'

class DmarcReport
  def initialize
    @dir = ARGV.shift
    @reports = []    
  end

  attr :reports

  def parse
    entities = Dir.children(@dir)
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
    
        records = []
        doc.xpath('feedback/record').each do |rx|
          r = {}
          r[:ip] = rx.at_xpath("row/source_ip").text
          r[:count] = rx.at_xpath("row/count").text.to_i
          r[:row] = {
            disp: rx.at_xpath("row/policy_evaluated/disposition").text,
            dkim: rx.at_xpath("row/policy_evaluated/dkim").text,
            spf: rx.at_xpath("row/policy_evaluated/spf").text
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

    @reports.each do |report|
      report[:records].each do |record|
        dkim_passed = record[:row][:dkim]&.downcase == "pass"
        spf_passed = record[:row][:spf]&.downcase == "pass"
        dmarc_passed = dkim_passed | spf_passed
        num = record[:count]
        dkim[dkim_passed ? :pass : :fail] += num
        spf[spf_passed ? :pass : :fail] += num
        dmarc[dmarc_passed ? :pass : :fail] += num
        ip_addr[dmarc_passed ? :pass : :fail][record[:ip]] += num
        volume_total += num
      end
    end

    top_fail_ipaddr = ip_addr[:fail].keys.sort_by {|k| ip_addr[:fail][k] }.reverse[0, 10]

    puts "***DMARC report summary"
    puts
    printf "%12s #{@reports.length}\n", "Total:"
    printf "%12s #{color_grn("pass")} %d / #{color_red("fail")} %d - %s%% passed  \n", "SPF:", spf[:pass], spf[:fail], pass_pct_color(spf[:pass].to_f / volume_total * 100)
    printf "%12s #{color_grn("pass")} %d / #{color_red("fail")} %d - %s%% passed  \n", "DKIM:", dkim[:pass], dkim[:fail], pass_pct_color(dkim[:pass].to_f / volume_total * 100)
    printf "%12s #{color_grn("pass")} %d / #{color_red("fail")} %d - %s%% passed  \n", "DMARC:", dmarc[:pass], dmarc[:fail], pass_pct_color(dmarc[:pass].to_f / volume_total * 100)
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

  def color_red str
    "\e[31m#{str}\e[0m"
  end

  def color_mag str
    "\e[35m#{str}\e[0m"
  end

  def color_yel str
    "\e[33m#{str}\e[0m"
  end

  def color_grn str
    "\e[32m#{str}\e[0m"
  end

  def color_blu str
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
end


d = DmarcReport.new
d.parse
d.summary
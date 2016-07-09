package com.firewall.view;

import java.io.*;
import java.util.Vector;

public class ApplyRule {
	public static int play(int flag, Vector<Vector<Object>> data) {
		/** flag
		 * bit 1 - 限制SYN请求速度
		 * bit 2 - 防止DOS攻击
		 * bit 3 - 限制单个IP访问量
		 * bit 4 - 木马反弹
		 * bit 5 - 禁止FTP, Telnet
		 * bit 6 - 防止ping攻击
		 */
		boolean[] choose = new boolean[6];
		for (int i = 0; i < 6; i++)
			choose[i] = ((flag & (1 << i)) > 0); // 分离出1~6位
		File script = new File("file/script.sh"); // 打开script.sh
		if (!script.exists()) {
			try {
				script.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
				return -1;
			}
		}
		FileWriter fileWritter;
		try {
			fileWritter = new FileWriter(script.getAbsolutePath());
		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		}
		BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
		try {
			bufferWritter.write("#!/bin/sh\niptables -F\n"); // 写入shell头部和清空iptables命令
			for (Vector<Object> v : data) { // 输出每一条自定义规则
				bufferWritter.write("iptables -I " + (String) v.get(0) + " ");
				String s = (String) v.get(1);
				if (s.length() > 0)
					bufferWritter.write("-s " + s + " ");
				s = (String) v.get(3);
				if (s.length() > 0)
					bufferWritter.write("-p tcp --sport " + s + " ");
				s = (String) v.get(2);
				if (s.length() > 0)
					bufferWritter.write("-d " + s + " ");
				s = (String) v.get(4);
				if (s.length() > 0)
					bufferWritter.write("-p tcp --dport " + s + " ");
				if (v.get(5).equals("允许"))
					bufferWritter.write("-j ACCEPT\n");
				else
					bufferWritter.write("-j DROP\n");
			}
			// 输出一键规则
			if (choose[0]) {
				bufferWritter.write("iptables -I INPUT -p tcp --syn -m connlimit --connlimit-above 15 -j DROP\n");
			}
			if (choose[1]) {
				bufferWritter.write(
					"iptables -I INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j DROP\n" +
					"iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH\n" +
					"iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 300 --hitcount 3 --name SSH -j DROP\n"
				);  
			}
			if (choose[2]) {
				bufferWritter.write("iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 30 -j DROP\n");
			}
			if (choose[3]) {
				bufferWritter.write("iptables -A OUTPUT -m state --state NEW -j DROP\n");
			}
			if (choose[4]) {
				bufferWritter.write("iptables -A OUTPUT -p tcp --sport 21 -j DROP\n");
				bufferWritter.write("iptables -A INPUT -p tcp --dport 21 -j DROP\n");
				bufferWritter.write("iptables -A OUTPUT -p tcp --sport 23 -j DROP\n");
				bufferWritter.write("iptables -A INPUT -p tcp --dport 23 -j DROP\n");
			}
			if (choose[5]) {
				bufferWritter.write("iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/m -j ACCEPT");
			}
	        bufferWritter.close();
	        if (!writeIptables())
	        	return -3;
		} catch (IOException e) {
			e.printStackTrace();
			return -2;
		}
		return 0;
	}
	
	private static boolean writeIptables() {
		Process p;

		try {
			p = Runtime.getRuntime().exec("sh file/script.sh"); // 执行脚本
			try {
				p.waitFor();
				if (p.exitValue() != 255)
					return true;
				else
					return false;
			} catch (InterruptedException e) {
				return false;
			}
		} catch (IOException e) {
			return false;
		}
	}
}

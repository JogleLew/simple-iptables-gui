package com.firewall.view;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.management.modelmbean.ModelMBean;
import javax.swing.*;

@SuppressWarnings("serial")
public class HomePage extends JFrame implements ActionListener {
	JLabel tableTitle;
	JButton jb_add, jb_del, jb_submit;
	JCheckBox func_syn, func_dos, func_tcp, func_trojan, func_port, func_ping;
	Vector<Object> columnNames;
	Vector<Vector<Object>> rowData;
	JTable jt_rule;
	JScrollPane jsp_center;
	public static int rulenum = 6;

	@Override
	public void actionPerformed(ActionEvent e) {
		if(e.getSource() == jb_add){
			new AddRulePage(this);
		}
		else if(e.getSource() == jb_del){
			int row = jt_rule.getSelectedRow();
			deleteConfig(row);
			refresh();
		}
		else if (e.getSource() == jb_submit) {
			boolean[] choose = {
				func_syn.isSelected(), 
				func_dos.isSelected(), 
				func_tcp.isSelected(), 
				func_trojan.isSelected(), 
				func_port.isSelected(), 
				func_ping.isSelected()
			};
			int flag = 0;
			for (int i = choose.length - 1; i >= 0 ; i--)
				flag = 2 * flag + (choose[i] ? 1 : 0);
			if (ApplyRule.play(flag, rowData) == 0)
				JOptionPane.showMessageDialog(null, "规则应用成功", "提示",
						JOptionPane.INFORMATION_MESSAGE);
			else if (ApplyRule.play(flag, rowData) == -1)
				JOptionPane.showMessageDialog(null, "无法打开文件，规则应用失败", "提示",
						JOptionPane.ERROR_MESSAGE);
			else if (ApplyRule.play(flag, rowData) == -2)
				JOptionPane.showMessageDialog(null, "写入文件出错，规则应用失败", "提示",
						JOptionPane.ERROR_MESSAGE);
			else if (ApplyRule.play(flag, rowData) == -3)
				JOptionPane.showMessageDialog(null, "写入iptables失败，请检查权限", "提示",
						JOptionPane.ERROR_MESSAGE);
			else
				JOptionPane.showMessageDialog(null, "规则应用失败", "提示",
						JOptionPane.ERROR_MESSAGE);
		}
	}

	public HomePage() {
		this.setLayout(null);

		tableTitle = new JLabel("过滤规则");
		tableTitle.setBounds(20, 5, 100, 25);
		this.add(tableTitle, null);

		columnNames = new Vector<>();
		columnNames.add("过滤表");
		columnNames.add("源IP");
		columnNames.add("目的IP");
		columnNames.add("源端口");
		columnNames.add("目的端口");
		columnNames.add("允许/丢弃");
		rowData = new Vector<>();
		getConfig();
		jt_rule = new JTable(rowData, columnNames) {
			public boolean isCellEditable(int row, int column) { 
			    return false;
			}
		};
		jsp_center = new JScrollPane(jt_rule);
		jsp_center.setBounds(20, 30, 460, 200);
		this.add(jsp_center, null);

		jb_add = new JButton("添加");
		jb_add.setBounds(20, 240, 50, 25);
		jb_add.addActionListener(this);
		this.add(jb_add, null);

		jb_del = new JButton("删除");
		jb_del.setBounds(100, 240, 50, 25);
		jb_del.addActionListener(this);
		this.add(jb_del, null);

		func_syn = new JCheckBox("限制SYN请求数量");
		func_syn.setBounds(20, 270, 230, 25);
		this.add(func_syn, null);

		func_dos = new JCheckBox("防止DOS攻击");
		func_dos.setBounds(20, 300, 230, 25);
		this.add(func_dos, null);

		func_tcp = new JCheckBox("限制单个IP访问量");
		func_tcp.setBounds(20, 330, 230, 25);
		this.add(func_tcp, null);

		func_trojan = new JCheckBox("防止反弹型木马");
		func_trojan.setBounds(250, 270, 400, 25);
		this.add(func_trojan, null);

		func_port = new JCheckBox("禁止FTP, Telnet");
		func_port.setBounds(250, 300, 400, 25);
		this.add(func_port, null);

		func_ping = new JCheckBox("防止ping攻击");
		func_ping.setBounds(250, 330, 400, 25);
		this.add(func_ping, null);

		jb_submit = new JButton();
		jb_submit.setText("应用规则");
		jb_submit.setBounds(380, 380, 100, 25);
		jb_submit.addActionListener(this);
		this.add(jb_submit);

		this.setBounds(0, 0, 500, 450);
		this.setVisible(true);
		this.setTitle("firewall");
		this.setLocationRelativeTo(null);
		this.setDefaultCloseOperation(EXIT_ON_CLOSE);
		this.setResizable(false);
	}

	public void refresh() {
		rowData.removeAllElements();
		getConfig();
		jt_rule.updateUI();
	}

	private void getConfig() {
		File f = new File("file");
		if (!f.exists())
			f.mkdir();
		File config = new File("file/config.txt"); // 打开config.txt
		if (!config.exists()) {
			try {
				config.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(config)); // 读取配置文件
			String rule = null;
			while ((rule = br.readLine()) != null) {
				String[] value = rule.split("#");
				Vector<Object> vector = new Vector<>();
				vector.add((value[0].trim().equals("0")) ? "INPUT" : 
					(value[0].trim().equals("1") ? "FORWARD" : "OUTPUT"));
				for (int i = 1; i < value.length - 1; i++)
					vector.add(value[i]);
				vector.add((value[value.length - 1].trim().equals("0")) ? "丢弃" : "允许");
				rowData.add(vector);
			}

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void deleteConfig(int row) {
		// System.out.println(row);
		File file = new File("file/config.txt"); // 打开配置文件
		BufferedReader br = null;
		FileOutputStream out = null;
		List<String> list = new ArrayList<String>();
		try {
			br = new BufferedReader(new FileReader(file)); // 读取配置文件，跳过要删除的一行
			int tp = -1;
			String text = br.readLine();
			tp++;
			while (text != null) {
				if (tp != row) {
					list.add(text + "\r\n");
				}
				text = br.readLine();
				tp++;
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		try {
			out = new FileOutputStream("file/config.txt"); // 写回配置文件
			for (String s : list) {
				// System.out.println(s);
				out.write(s.getBytes());
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (out != null)
					out.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static boolean testRoot() {
		Process p;

		try {
			p = Runtime.getRuntime().exec("su"); // 允许命令su

			DataOutputStream os = new DataOutputStream(p.getOutputStream());
			os.writeBytes("echo \"Do I have root?\" >/system/sd/temporary.txt\n");
			os.writeBytes("exit\n");
			os.flush();

			try {
				p.waitFor();
				if (p.exitValue() != 255) // 正常退出，说明是管理员权限
					return true;
				else // 否则不是管理员权限
					return false;
			} catch (InterruptedException e) {
				return false;
			}
		} catch (IOException e) {
			return false;
		}
	}

	public static void main(String[] args) {
		try {
			UIManager.setLookAndFeel("com.jtattoo.plaf.acryl.AcrylLookAndFeel"); // 设置外观
		} catch (Exception e) {
			e.printStackTrace();
		}
		boolean isRoot = testRoot(); // 测试是否为管理员权限
		if (isRoot) {
			HomePage page = new HomePage();
		} else {
			JOptionPane.showMessageDialog(null, "程序需要以管理员权限运行，请以sudo java -jar firewall.jar方式打开", "提示",
					JOptionPane.ERROR_MESSAGE);
		}
	}

}

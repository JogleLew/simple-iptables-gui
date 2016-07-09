package com.firewall.view;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

@SuppressWarnings("serial")
public class AddRulePage extends JFrame implements ActionListener{

	JPanel jp_main,jp_center;
	JComboBox comboBox1, comboBox2;
	JLabel[] jl_colname;
	JTextField[] jtf_value;
	JButton jb_save_and_exit;
	HomePage hp;
	
	@Override
	public void actionPerformed(ActionEvent e) {
		if(e.getSource() == jb_save_and_exit){
			if(issValid()){
				writeInConfig();
				hp.refresh();
				this.dispose();
			}
			else
				JOptionPane.showMessageDialog(null, "请检查输入信息的格式", "提示",JOptionPane.ERROR_MESSAGE);
		}
	}
	
	private void writeInConfig(){
		File config = new File("file/config.txt");
		BufferedWriter bw = null;
		try {
			bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(config, true)));  // 将新增的规则写入文件末尾
			String rule = "";
			int table = comboBox2.getSelectedIndex();
			rule += table + "#";
			for(int i = 0 ; i < HomePage.rulenum - 2; i++)
				rule += ( jtf_value[i].getText()+"#");
			String isEnable = (String)comboBox1.getSelectedItem();
			if(isEnable.equals("丢弃"))
				rule += ("0\n");
			else 
				rule += ("1\n");
			bw.write(rule);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if(bw!=null)
					bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	private boolean issValid(){ // 判断输入是否正确
		String tmp = "";
		int allNull = 0;
		for(int i = 0 ; i < 2 ; i++){
			tmp = jtf_value[i].getText();
			if(tmp==null || tmp.equals("")){
				allNull ++;
				continue;
			}
			
			String[] ipmask = tmp.split("/");
			if (ipmask.length > 2)
				return false;
			if (ipmask.length == 2) {
				try{
					int num = Integer.valueOf(ipmask[1]);
					if (num < 0 || num > 32)
						return false;
				} catch (Exception e) {
					return false;
				}
				tmp = ipmask[0];
			}
			String[] parts = tmp.split("\\.");
//			System.out.println(parts.length);
//			for(int j = 0 ; j < 4 ; j++){
//				System.out.println(parts[i]);
//			}
			if(parts.length!=4)
				return false;
			else{
				for(int j = 0 ; j < 4 ; j++){
					try {
						int num = Integer.valueOf(parts[j]);
						if(num <0 || num > 255)
							return false;
					} catch (Exception e) {
						return false;
					}
				}
			}
		}
		for(int i = 2 ; i < 4 ; i ++){
			try {
				tmp = jtf_value[i].getText();
				if(tmp==null ||tmp.equals("")){
					allNull ++;
					continue;
				}
				int num = Integer.valueOf(tmp);
				if(num <0 || num > 65535 )
					return false;
			} catch (Exception e) {
				return false;
			}
		}
		return (allNull == 4)?false : true;
	}
	
	
	public AddRulePage(HomePage hp){
		this.hp = hp;
		
		jb_save_and_exit = new JButton("保存并退出");
		jb_save_and_exit.addActionListener(this);
		
		int rulenum = HomePage.rulenum;
		
		jl_colname = new JLabel[rulenum];
		jl_colname[0] = new JLabel("过滤表");
		jl_colname[1] = new JLabel("源IP");
		jl_colname[2] = new JLabel("目的IP");
		jl_colname[3] = new JLabel("源端口");
		jl_colname[4] = new JLabel("目的端口");
		jl_colname[5] = new JLabel("允许/丢弃");
		
		String[] choose1 = {"丢弃", "允许"};
		comboBox1 = new JComboBox(choose1);
		jtf_value = new JTextField[rulenum - 2];
		for(int i = 0 ; i < rulenum - 2 ; i++){
			jtf_value[i] = new JTextField(10);
			jtf_value[i].setText("");
		}
		String[] choose2 = {"INPUT", "FORWARD", "OUTPUT"};
		comboBox2 = new JComboBox(choose2);
		
		jp_center = new JPanel(new GridLayout(rulenum, 2));
		jp_center.add(jl_colname[0]);
		jp_center.add(comboBox2);
		for(int i = 1; i < rulenum - 1; i++){
			jp_center.add(jl_colname[i]);
			jp_center.add(jtf_value[i - 1]);
		}
		jp_center.add(jl_colname[rulenum - 1]);
		jp_center.add(comboBox1);
		
		jp_main = new JPanel();
		jp_main.add(jp_center);
		jp_main.add(jb_save_and_exit,BorderLayout.SOUTH);
		this.add(jp_main);
		
		this.setBounds(100, 100, 350, 220);
		this.setVisible(true);
		this.setTitle("firewall");
	}

}

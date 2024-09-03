package com.abbypan.ctca;

import javax.net.ssl.HttpsURLConnection;

import org.openjdk.jmh.annotations.*;
import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.*;

import com.abbypan.ctca.CTCA; 

@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class CTCATest {

	 public static void main(String[] args) {
		 CTCATest tt = new CTCATest();

		 ctcaConn();
		  }

	 @Test
	  public void benchmark() throws Exception {
	    org.openjdk.jmh.Main.main(new String[]{CTCATest.class.getName()});
	  }
	 
	@Benchmark
	    public void ctcaConn() {
	        // Benchmark code to be measured
		String[] para = { "https://www.baidu.com", "ctca", "src/main/resources/example.cache" };
		 CTCA ctca = new CTCA(); 
		 HttpsURLConnection con = ctca.create_main_conn(para);
		 ctca.print_content(con);
	    }
}

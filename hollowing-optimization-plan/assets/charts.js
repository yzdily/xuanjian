(function() {
  // Read CSS variables
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim() || '#2563eb';
  var accent2 = style.getPropertyValue('--accent2').trim() || '#dc2626';
  var accent3 = style.getPropertyValue('--accent3').trim() || '#f59e0b';
  var accent4 = style.getPropertyValue('--accent4').trim() || '#059669';
  var ink = style.getPropertyValue('--ink').trim() || '#1a1d29';
  var muted = style.getPropertyValue('--muted').trim() || '#6b7280';
  var rule = style.getPropertyValue('--rule').trim() || '#e5e7eb';
  var bg2 = style.getPropertyValue('--bg2').trim() || '#ffffff';

  // Initialize Mermaid
  if (typeof mermaid !== 'undefined') {
    mermaid.initialize({
      startOnLoad: true,
      theme: 'neutral',
      securityLevel: 'loose',
      flowchart: { useMaxWidth: true, htmlLabels: true, curve: 'basis' },
      gantt: { useMaxWidth: true, fontSize: 12 }
    });
  }

  // --- Chart 1: Checklist Execution Result Distribution ---
  var chart1El = document.getElementById('chart-checklist');
  if (chart1El && typeof echarts !== 'undefined') {
    var chart1 = echarts.init(chart1El, null, { renderer: 'svg' });
    chart1.setOption({
      animation: false,
      tooltip: {
        trigger: 'item',
        appendToBody: true,
        formatter: '{b}: {c} 项 ({d}%)'
      },
      legend: {
        bottom: 10,
        textStyle: { color: muted, fontSize: 12 },
        itemWidth: 14,
        itemHeight: 14,
        itemGap: 20
      },
      color: [accent2, accent3, muted],
      series: [{
        type: 'pie',
        radius: ['42%', '68%'],
        center: ['50%', '42%'],
        avoidLabelOverlap: true,
        itemStyle: {
          borderRadius: 6,
          borderColor: bg2,
          borderWidth: 2
        },
        label: {
          show: true,
          formatter: '{b}\n{c} 项',
          color: ink,
          fontSize: 13,
          fontWeight: 600
        },
        labelLine: {
          lineStyle: { color: rule },
          length: 15,
          length2: 15
        },
        data: [
          { value: 429, name: '跳过（FAST模式）' },
          { value: 173, name: '未测（WAF封禁）' },
          { value: 0, name: '真实完成' }
        ]
      }],
      title: {
        subtext: '总计 602 项 Checklist',
        subtextStyle: { color: muted, fontSize: 12 },
        left: 'center',
        top: 5
      }
    });
    window.addEventListener('resize', function() { chart1.resize(); });
  }

  // --- Chart 2: Root Cause Impact Weight ---
  var chart2El = document.getElementById('chart-rootcause');
  if (chart2El && typeof echarts !== 'undefined') {
    var chart2 = echarts.init(chart2El, null, { renderer: 'svg' });
    chart2.setOption({
      animation: false,
      tooltip: {
        trigger: 'axis',
        appendToBody: true,
        axisPointer: { type: 'shadow' },
        formatter: function(params) {
          var p = params[0];
          return p.name + '<br/>影响权重: ' + p.value + '%';
        }
      },
      grid: {
        left: '8%',
        right: '8%',
        top: 30,
        bottom: 60,
        containLabel: true
      },
      xAxis: {
        type: 'value',
        max: 30,
        axisLabel: { color: muted, fontSize: 11, formatter: '{value}%' },
        splitLine: { lineStyle: { color: rule, type: 'dashed' } },
        axisLine: { lineStyle: { color: rule } }
      },
      yAxis: {
        type: 'category',
        data: [
          'RC6 补测链路断裂',
          'RC5 目录路径污染',
          'RC4 WAF封禁中断',
          'RC3 mitmproxy故障',
          'RC2 FAST模式全跳过',
          'RC1 CRUD推测虚假端点'
        ],
        axisLabel: { color: ink, fontSize: 12 },
        axisLine: { lineStyle: { color: rule } },
        axisTick: { show: false }
      },
      series: [{
        type: 'bar',
        data: [
          { value: 17, itemStyle: { color: accent3 } },
          { value: 8, itemStyle: { color: accent3 + 'cc' } },
          { value: 17, itemStyle: { color: accent2 + 'dd' } },
          { value: 13, itemStyle: { color: accent2 + 'cc' } },
          { value: 20, itemStyle: { color: accent2 } },
          { value: 25, itemStyle: { color: accent2 } }
        ],
        barWidth: '55%',
        itemStyle: { borderRadius: [0, 4, 4, 0] },
        label: {
          show: true,
          position: 'right',
          formatter: '{c}%',
          color: muted,
          fontSize: 11,
          fontWeight: 600
        }
      }]
    });
    window.addEventListener('resize', function() { chart2.resize(); });
  }

})();

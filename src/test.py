def fetch_data_from_db():   # DB에서 데이터를 가져오는 함수
    
    cursor.execute("SELECT * FROM operation_logs")
    
    operation_logs = cursor.fetchall()

    return {
        "operation_logs": operation_logs
    }

def generate_docx_report(report_data, output_file): # .docx 형식으로 보고서를 생성하는 함수
    
    document = Document()

    document.add_heading('Anti Signature Report', 0)
    
    document.add_paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    document.add_paragraph('')

    # Operation Logs
    document.add_heading('Operation Logs', level=1)
    
    for log in report_data["operation_logs"]:
        
        document.add_paragraph(f"Operation: {log[1]}, Details: {log[2]}, Status: {log[3]}, Timestamp: {log[4]}")

    # 저장
    document.save(output_file)
   
    print(f".docx 보고서가 {output_file}에 저장되었습니다.")
    
def generate_hwp_report(report_data, output_file): # .hwp 형식으로 보고서를 생성하는 함수
    
    document = Document()

    document.add_heading('Anti Signature Report', 0)
    
    document.add_paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    document.add_paragraph('')

    # Operation Logs
    document.add_heading('Operation Logs', level=1)
    
    for log in report_data["operation_logs"]:
        
        document.add_paragraph(f"Operation: {log[1]}, Details: {log[2]}, Status: {log[3]}, Timestamp: {log[4]}")

    # 저장
    document.save(output_file)
   
    print(f".docx 보고서가 {output_file}에 저장되었습니다.")

def generate_html_report(report_data, output_file):     # HTML 형식으로 보고서를 생성하는 함수
    
    html_content = f"""
    
    <html>
    <head>
        <title>Anti Signature Report</title>
    </head>
    <body>
        <h1>Anti Signature Report</h1>
        <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h2>Operation Logs</h2>
        <ul>
    
    """
    # Operation Logs
    for log in report_data["operation_logs"]:
   
        html_content += f"<li>Operation: {log[1]}, Details: {log[2]}, Status: {log[3]}, Timestamp: {log[4]}</li>"
   
    html_content += "</ul>"

    with open(output_file, 'w') as f:
   
        f.write(html_content)
   
    print(f"HTML 보고서가 {output_file}에 저장되었습니다.")
    
    
def process_report_option(report_format):  #  보고서 생성 옵션 처리

    # DB에서 데이터 가져오기
    report_data = fetch_data_from_db()

    # 보고서 형식에 따른 처리
    if report_format == 'docx':

        output_file = 'anti_signature_report.docx'

        generate_docx_report(report_data, output_file)
        
    elif report_format == 'html':

        output_file = 'anti_signature_report.html'

        generate_html_report(report_data, output_file)
        
    elif report_format =- 'hwp':
        
        output_file = 'anti_signature_report.hwp'
        
        generate_hwp_report(report_data, output_file)

    else:

        print("지원하지 않는 형식입니다. docx 또는 html을 선택하세요.")


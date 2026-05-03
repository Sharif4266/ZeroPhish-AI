import zipfile
import xml.etree.ElementTree as ET
import sys

def extract_text_from_docx(docx_path):
    try:
        with zipfile.ZipFile(docx_path, 'r') as docx:
            xml_content = docx.read('word/document.xml')
            tree = ET.fromstring(xml_content)
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            paragraphs = tree.findall('.//w:p', namespaces=ns)
            texts = []
            for p in paragraphs:
                texts.append(''.join(node.text for node in p.findall('.//w:t', namespaces=ns) if node.text))
            return '\n'.join(texts)
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(extract_text_from_docx(sys.argv[1]))

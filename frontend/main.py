import gradio as gr
import requests

def check_url(url):
    try:
        response = requests.post("http://127.0.0.1:8000/model", json={"url_name": url})
        print(f"Response status code: {response.status_code}")  # Debugging
        print(f"Response JSON: {response.json()}")  # Debugging
        return response.json()
    except Exception as e:
        print(f"An error occurred: {e}")  # Debugging
        return {"output": "Error connecting to the server.", "success": False}

def process_url(url):
    result = check_url(url)  # Call the synchronous function directly
    if result['success']:
        return f'<span style="color: white;">{result["output"]}</span>'
    else:
        return f'<span style="color: red;">{result["output"]}</span>'

with gr.Blocks() as demo:
    gr.Markdown("<h1 style='text-align: center;'>PHISHWATCH</h1>")

    with gr.Row():
        url_input = gr.Textbox(label="Enter URL")
        submit_btn = gr.Button("Test")

    with gr.Row():
        output_text = gr.HTML(value="<span>Result will be displayed here</span>")

    def update_output(url):
        print(f"URL entered: {url}")  # Debugging
        message = process_url(url)
        print(f"Message to display: {message}")  # Debugging
        return message

    submit_btn.click(
        fn=update_output,
        inputs=[url_input],
        outputs=[output_text]
    )

demo.launch()

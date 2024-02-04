import numpy as np
from transformers import ConvNextImageProcessor, ConvNextForImageClassification
from datasets import load_dataset

processor = ConvNextImageProcessor.from_pretrained("facebook/convnext-base-384-22k-1k", cache_dir="./cache")
HFmodel = ConvNextForImageClassification.from_pretrained("facebook/convnext-base-384-22k-1k", cache_dir="./cache").eval()
model = next(HFmodel.modules())

dataset = load_dataset("huggingface/cats-image", cache_dir="./cache", trust_remote_code=True)
np_original = np.array(dataset["test"]["image"][0])
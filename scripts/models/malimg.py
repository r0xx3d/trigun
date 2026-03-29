import numpy as np
from tensorflow.keras.models import load_model
from PIL import Image
import sys

def bin2gray(binary_path, target_size=(64,64)):
    with open(binary_path,'rb') as f:
        byte_array = np.frombuffer(f.read(), dtype=np.uint8)

        # padding and truncation
        n_pixels = target_size[0] * target_size[1]
        if byte_array.size < n_pixels:
            byte_array = np.pad(byte_array, (0, n_pixels - byte_array.size), 'constant', constant_values=0)
        else:
            byte_array = byte_array[:n_pixels]

        # reshaping for grayscale
        img_array = byte_array.reshape(target_size)
        return img_array

def malimg(model_path, binary_path, class_names, img_size=(64,64)):
    
    model = load_model(model_path)

    img = bin2gray(binary_path, target_size=img_size)
    img_input = img.astype(np.float32) / 255.0
    input_shape = model.input_shape
    if input_shape[-1] == 1:
        img_input = img_input[np.newaxis, ...,np.newaxis]
    elif input_shape[-1] == 3:
        img_input = img_input[np.newaxis, ..., np.newaxis]
        img_input = np.repeat(img_input, 3, axis=-1)
    else:
        raise ValueError(f"Unexpected input channel count: {input_shape[-1]}")

    preds = model.predict(img_input)
    label_index = np.argmax(preds[0])
    label_name = class_names[label_index]
    return label_name, preds[0]

if __name__ == "__main__":
    malimg_classes = [
        'Adialer.C', 'Agent.FYI', 'Allaple.A', 'Allaple.L', 'Alueron.gen!J',
        'Autorun.K', 'C2LOP.P', 'C2LOP.gen!g', 'Dialplatform.B', 'Dontovo.A',
        'Fakerean', 'Instantaccess', 'Lolyda.AA1', 'Lolyda.AA2', 'Lolyda.AA3',
        'Lolyda.AT', 'Malex.gen!J', 'Obfuscator.AD', 'Rbot!gen', 'Skintrim.N',
        'Swizzor.gen!E', 'Swizzor.gen!I', 'VB.AT', 'Wintrim.BX', 'Yuner.A'
    ]
    model_h5 = "./scripts/models/malimg_cnn.h5"
    binpath = sys.argv[1]
    predicted_label, raw_scores = malimg(model_h5, binpath, malimg_classes)
    print(f"Potential malware class: {predicted_label}")
    print(f"Class probabilities: {raw_scores}")

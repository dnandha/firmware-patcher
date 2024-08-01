import streamlit as st
from mi_patcher import MiPatcher
from base_patcher import BasePatcher, patch

# Initialize the Streamlit app
st.title("NGFW Patcher")
st.write("Configure your device settings using the sliders below.")

# Create a device selection menu
device_options = ["1s", "pro2", "lite", "3", "4pro"]
selected_device = st.selectbox("Select your device", device_options)

# Initialize the patcher with dummy data
data = bytearray(100)  # Example data, replace with actual data
patcher = MiPatcher(data)

# Fetch default values for the selected device
device_defaults = patcher.get_defaults(selected_device)

# Iterate over the methods in BasePatcher that have the patch decorator
for method_name in dir(BasePatcher):
    method = getattr(BasePatcher, method_name)
    if hasattr(method, 'label'):
        # Get the decorator attributes
        label = method.label
        description = method.description
        min_value = method.min
        max_value = method.max

        # Get the default value for the selected device
        default_value = device_defaults.get(method_name, min_value)

        # Create a slider for the method
        st.slider(
            label=description,
            min_value=min_value,
            max_value=max_value,
            value=default_value,
            key=method_name
        )
import streamlit as st
from mi_patcher import MiPatcher
from base_patcher import BasePatcher, patch, PatchGroup

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

# Group patches by their group
grouped_patches = {}
for method_name in dir(BasePatcher):
    method = getattr(BasePatcher, method_name)
    if hasattr(method, 'label'):
        group = method.group
        if group not in grouped_patches:
            grouped_patches[group] = []
        grouped_patches[group].append(method)

# Sort groups by name
sorted_groups = sorted(grouped_patches.items(), key=lambda item: item[0].value)

# Iterate over the sorted grouped patches
for group, methods in sorted_groups:
    st.subheader(group.value)
    
    # First, display all checkboxes
    for method in methods:
        label = method.label
        description = f"Activate {label} ({method.description})"

        if method.min is None or method.max is None:
            # Add a checkbox for methods without min or max values
            st.checkbox(description, key=label)

    # Then, display sliders with an additional checkbox to activate/deactivate them
    for method in methods:
        label = method.label
        description = method.description

        if method.min is not None and method.max is not None:
            # Add a checkbox to activate or deactivate the slider
            is_active = st.checkbox(f"Activate {label}", key=f"{label}_active")

            if is_active:
                # Get the default value for the selected device
                default_value = device_defaults.get(label, 0)
                step = 1 if isinstance(default_value, int) else 0.1
                min_value = int(method.min) if step == 1 else float(method.min)
                max_value = int(method.max) if step == 1 else float(method.max)

                # Create a slider for the method
                st.slider(
                    label=description,
                    min_value=min_value,
                    max_value=max_value,
                    value=default_value,
                    step=step,
                    key=label
                )
use std::io::Result;

fn main() -> Result<()> {
    #[cfg(feature = "tauri-app")]
    tauri_build::build();

    prost_build::compile_protos(
        &[
            "ProtobufSource/device_to_device_messages.proto",
            "ProtobufSource/offline_wire_formats.proto",
            "ProtobufSource/securegcm.proto",
            "ProtobufSource/securemessage.proto",
            "ProtobufSource/ukey.proto",
            "ProtobufSource/wire_format.proto",
        ],
        &["ProtobufSource"],
    )?;
    Ok(())
}

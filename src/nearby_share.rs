use core::panic;
use crypto_bigint::generic_array::GenericArray;
use hmac_sha256::HMAC;
use num::BigInt;
use openssl::rand::rand_bytes;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::EncodedPoint;
use p256::{PublicKey, SecretKey};
use prost::Message;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::vec;

use location::nearby::connections::connection_response_frame::ResponseStatus;
use location::nearby::connections::offline_frame::Version;
use location::nearby::connections::os_info::OsType;
use location::nearby::connections::payload_transfer_frame::payload_header::PayloadType;
use location::nearby::connections::payload_transfer_frame::PayloadChunk;
use location::nearby::connections::payload_transfer_frame::PayloadHeader;
use location::nearby::connections::v1_frame::FrameType;
use location::nearby::connections::ConnectionResponseFrame;
use location::nearby::connections::KeepAliveFrame;
use location::nearby::connections::OfflineFrame;
use location::nearby::connections::OsInfo;
use location::nearby::connections::PayloadTransferFrame;
use location::nearby::connections::V1Frame;
use securegcm::ukey2_message::Type::*;
use securegcm::DeviceToDeviceMessage;
use securegcm::GcmMetadata;
use securemessage::EncScheme;
use securemessage::Header;
use securemessage::HeaderAndBody;
use securemessage::SecureMessage;
use securemessage::SigScheme;
use securemessage::{GenericPublicKey, PublicKeyType};
use sharing::nearby::connection_response_frame::Status;
use sharing::nearby::Frame;

pub mod location {
    pub mod nearby {
        pub mod connections {
            include!(concat!(env!("OUT_DIR"), "/location.nearby.connections.rs"));
        }
    }
}

pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}
pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}
pub mod sharing {
    pub mod nearby {
        include!(concat!(env!("OUT_DIR"), "/sharing.nearby.rs"));
    }
}

#[derive(Clone, Copy)]
struct CryptoKeychain {
    client_key: [u8; 32],
    client_key_hmac: [u8; 32],
    server_key: [u8; 32],
    server_key_hmac: [u8; 32],
}

fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0)
}

fn as_4u8buf(val: u32) -> [u8; 4] {
    [
        ((val >> 24) & 0xff) as u8,
        ((val >> 16) & 0xff) as u8,
        ((val >> 8) & 0xff) as u8,
        ((val >> 0) & 0xff) as u8,
    ]
}

pub fn handle_client_init(
    stream: &mut TcpStream,
    download_path: PathBuf,
    ask_confirmation: impl FnOnce(&str, &str) -> bool,
) -> Option<String> {
    let mut rng = rand::thread_rng();
    let secret_key = p256::SecretKey::random(&mut rng);

    use securegcm::*;

    let connection_request_frame = OfflineFrame::decode(&read_packet(stream)[..])
        .unwrap()
        .v1
        .unwrap()
        .connection_request
        .unwrap();

    let endpoint_info = connection_request_frame.endpoint_info.unwrap();

    let device_name_len = endpoint_info[17];
    let raw_device_type = endpoint_info[0] & 7;
    let _device_type = DeviceType::try_from(raw_device_type as i32).unwrap_or(DeviceType::Unknown);

    let sending_device_name = String::from_utf8(
        endpoint_info
            .iter()
            .cloned()
            .skip(18)
            .take(device_name_len as usize)
            .collect::<Vec<u8>>(),
    )
    .unwrap();

    let buf = read_packet(stream);
    let u2key_message = Ukey2Message::decode(&buf[..]).unwrap();

    let client_init_serialized_data = buf;
    let u2key_client_init =
        Ukey2ClientInit::decode(&u2key_message.message_data.unwrap()[..]).unwrap();

    assert_eq!(u2key_client_init.version.unwrap_or(0), 1);

    let rng = rand::thread_rng();
    let public_key = secret_key.public_key();

    let mut x_arr: [u8; 32] = [0; 32];
    let x_vec = public_key.to_encoded_point(false).x().unwrap().to_vec();
    let mut y_arr: [u8; 32] = [0; 32];
    let y_vec = public_key.to_encoded_point(false).y().unwrap().to_vec();
    for i in 0..32 {
        x_arr[i] = x_vec[i];
        y_arr[i] = y_vec[i];
    }

    use num::bigint::*;

    let signed_x = BigInt::from_bytes_be(Sign::Plus, &mut x_arr).to_signed_bytes_be();
    let signed_y = BigInt::from_bytes_be(Sign::Plus, &mut y_arr).to_signed_bytes_be();

    use securemessage::EcP256PublicKey;
    let key_message = GenericPublicKey {
        r#type: PublicKeyType::EcP256 as i32,
        ec_p256_public_key: Some(EcP256PublicKey {
            x: signed_x.to_vec(),
            y: signed_y.to_vec(),
        }),
        rsa2048_public_key: None,
        dh2048_public_key: None,
    };

    // random buffer
    let mut rand_buf = vec![0; 32];
    rand_bytes(&mut rand_buf).unwrap();
    let ukey2_server_init: Ukey2ServerInit = Ukey2ServerInit {
        version: Some(1),
        random: Some(rand_buf),

        handshake_cipher: Some(i32::from(Ukey2HandshakeCipher::P256Sha512)),
        public_key: Some(key_message.encode_to_vec()),
    };

    let ukey2_message = Ukey2Message {
        message_type: Some(ServerInit as i32),
        message_data: Some(ukey2_server_init.encode_to_vec()),
    };
    let server_init_serialized_data = ukey2_message.encode_to_vec();

    send_packet(stream, server_init_serialized_data.clone());
    // SENT SERVER INIT
    // RECEIVING CLIENT FINISH

    let u2key_message = Ukey2Message::decode(&read_packet(stream)[..]).unwrap();

    assert_eq!(u2key_message.message_type.unwrap_or(0), ClientFinish as i32);

    let ukey2_client_finished =
        Ukey2ClientFinished::decode(&u2key_message.message_data.unwrap().to_vec()[..]).unwrap();
    let keychain = gen_keychain(
        ukey2_client_finished,
        server_init_serialized_data,
        client_init_serialized_data,
        secret_key,
    );

    #[allow(deprecated)]
    let response = OfflineFrame {
        version: Some(Version::V1 as i32),
        v1: Some(location::nearby::connections::V1Frame {
            connection_response: Some(ConnectionResponseFrame {
                status: Some(0),
                response: Some(ResponseStatus::Accept as i32),
                os_info: Some(OsInfo {
                    r#type: Some(OsType::Linux as i32),
                }),
                ..Default::default()
            }),
            r#type: Some(FrameType::ConnectionResponse as i32),
            ..Default::default()
        }),
    };

    send_packet(stream, response.encode_to_vec());
    use sharing::nearby::V1Frame;

    let signed_data: Vec<u8> = rng
        .clone()
        .sample_iter(rand::distributions::Standard)
        .take(6)
        .collect();
    let secret_id_hash: Vec<u8> = rng
        .clone()
        .sample_iter(rand::distributions::Standard)
        .take(72)
        .collect();

    let paried_encryption = Frame {
        version: Some(Version::V1 as i32),
        v1: Some(V1Frame {
            paired_key_encryption: Some(sharing::nearby::PairedKeyEncryptionFrame {
                signed_data: Some(signed_data),
                secret_id_hash: Some(secret_id_hash),
                ..Default::default()
            }),
            r#type: Some(sharing::nearby::v1_frame::FrameType::PairedKeyEncryption as i32),
            ..Default::default()
        }),
    };

    let mut sequence_mutex: Arc<Mutex<i32>> = Arc::new(Mutex::new(1));
    send_encrypted_nearby_frame(
        stream,
        paried_encryption,
        &sequence_mutex.clone(),
        &keychain,
    );
    // Finished sending Paired key encryption

    let _connection_response = OfflineFrame::decode(&read_packet(stream)[..]);

    let mut filebuffer = Vec::<u8>::new();
    let _payload_type =
        receive_encrypted_nearby_frame(stream, &keychain, &mut filebuffer, &mut sequence_mutex);
    let _received_nearby_frame = Frame::decode(filebuffer.as_slice()).unwrap();

    // Paired key encryption sent and received

    // Sending paired key result
    let paired_key_result = sharing::nearby::Frame {
        version: Some(Version::V1 as i32),
        v1: Some(sharing::nearby::V1Frame {
            paired_key_result: Some(sharing::nearby::PairedKeyResultFrame {
                status: Some(sharing::nearby::paired_key_result_frame::Status::Unable as i32),
            }),
            r#type: Some(sharing::nearby::v1_frame::FrameType::PairedKeyResult as i32),
            ..Default::default()
        }),
    };

    send_encrypted_nearby_frame(stream, paired_key_result, &mut sequence_mutex, &keychain);

    // Receiving paired key result

    let mut filebuffer = Vec::<u8>::new();
    let _payload_type =
        receive_encrypted_nearby_frame(stream, &keychain, &mut filebuffer, &mut sequence_mutex);
    let received_nearby_frame = Frame::decode(filebuffer.as_slice()).unwrap();

    assert_eq!(
        received_nearby_frame
            .v1
            .unwrap()
            .paired_key_result
            .unwrap()
            .status
            .unwrap(),
        sharing::nearby::paired_key_result_frame::Status::Unable as i32
    );

    // Finished paired key encryption

    let mut filebuffer = Vec::<u8>::new();
    let _payload_type =
        receive_encrypted_nearby_frame(stream, &keychain, &mut filebuffer, &mut sequence_mutex);
    let received_nearby_frame = Frame::decode(filebuffer.as_slice()).unwrap();

    let introduction_frame = received_nearby_frame.v1.unwrap().introduction.unwrap();
    let file_metadata: &sharing::nearby::FileMetadata =
        introduction_frame.file_metadata.first().unwrap();
    let incoming_file_name = file_metadata.name.clone().unwrap();
    println!("Receiving file {}", incoming_file_name);

    let mut stream2 = stream.try_clone().unwrap();
    let mutex_clone = sequence_mutex.clone();
    let filename = incoming_file_name.clone();
    let handle = thread::spawn(move || {
        loop {
            let mut filebuffer = Vec::<u8>::new();
            let payload_type = receive_encrypted_nearby_frame(
                &mut stream2,
                &keychain,
                &mut filebuffer,
                &mutex_clone,
            );

            match payload_type {
                PayloadType::UnknownPayloadType => {
                    println!("Received unknown payload type");
                    break;
                }
                PayloadType::Bytes => {
                    let received_nearby_frame = Frame::decode(filebuffer.as_slice()).unwrap();
                    // println!("Received something {:?}", received_nearby_frame);

                    if received_nearby_frame.v1.unwrap().r#type.unwrap()
                        == FrameType::Disconnection as i32
                    {
                        println!("Received disconnection frame");
                        break;
                    }
                }
                PayloadType::File => {
                    println!("Received file {}\n", incoming_file_name);
                    use std::io::prelude::*;

                    if !download_path.exists() {
                        std::fs::create_dir_all(&download_path).unwrap();
                    }
                    let mut file = std::fs::File::create(download_path.join(incoming_file_name)).unwrap();
                    file.write_all(filebuffer.as_slice()).unwrap();

                    break;
                }
                PayloadType::Stream => panic!("Stream not implemented"),
            }
        }
    });

    let acceptance = ask_confirmation(&filename, &sending_device_name);
    if !acceptance {
        println!("Rejected connection\n");
    }

    let response_frame = Frame {
        version: Some(Version::V1 as i32),
        v1: Some(V1Frame {
            r#type: Some(sharing::nearby::v1_frame::FrameType::Response as i32),
            connection_response: Some(sharing::nearby::ConnectionResponseFrame {
                status: Some(match acceptance {
                    true => Status::Accept,
                    false => Status::Reject,
                } as i32),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };

    send_encrypted_nearby_frame(stream, response_frame, &mut sequence_mutex, &keychain);

    handle.join().unwrap();

    if !acceptance {
        return None;
    }

    Some(filename)
}

fn send_encrypted_nearby_frame(
    stream: &mut TcpStream,
    frame: Frame,
    sequence_number: &Arc<Mutex<i32>>,
    keychain: &CryptoKeychain,
) {
    let mut num = sequence_number.lock().unwrap();
    let body = frame.encode_to_vec();
    let mut rng = rand::thread_rng();
    let bodylen = body.len();
    let mut transfer = PayloadTransferFrame {
        packet_type: Some(1 as i32),
        payload_chunk: Some(PayloadChunk {
            flags: Some(0),
            offset: Some(0),
            body: Some(body),
        }),
        payload_header: Some(PayloadHeader {
            id: Some(rng.gen()),
            r#type: Some(1),
            total_size: Some(bodylen as i64),
            is_sensitive: Some(false),
            ..Default::default()
        }),
        control_message: None,
    };

    let wrapper = OfflineFrame {
        version: Some(Version::V1 as i32),
        v1: Some(location::nearby::connections::V1Frame {
            r#type: Some(3),
            payload_transfer: Some(transfer.clone()),
            ..Default::default()
        }),
    };

    send_packet(
        stream,
        encrypt_offline_frame(
            wrapper.clone(),
            keychain.server_key,
            keychain.server_key_hmac,
            *num,
        ),
    );

    *num += 1;

    transfer.payload_chunk = Some(PayloadChunk {
        flags: Some(1),
        offset: Some(bodylen as i64),
        body: None,
    });

    let wrapper = OfflineFrame {
        version: Some(Version::V1 as i32),
        v1: Some(location::nearby::connections::V1Frame {
            r#type: Some(3),
            payload_transfer: Some(transfer.clone()),
            ..Default::default()
        }),
    };

    send_packet(
        stream,
        encrypt_offline_frame(wrapper, keychain.server_key, keychain.server_key_hmac, *num),
    );

    *num += 1;
}

fn receive_encrypted_nearby_frame(
    stream: &mut TcpStream,
    keychain: &CryptoKeychain,
    framebuffer: &mut Vec<u8>,
    sequence_number: &Mutex<i32>,
) -> PayloadType {
    let mut chunk_id = 0;
    let mut frametype: PayloadType = PayloadType::UnknownPayloadType;
    loop {
        let sms_packet = SecureMessage::decode(&read_packet(stream)[..]).unwrap();
        let v1: V1Frame =
            decrypt_offline_frame(sms_packet, keychain.client_key, keychain.client_key_hmac)
                .v1
                .unwrap();

        match FrameType::try_from(v1.r#type.unwrap()).unwrap() {
            FrameType::UnknownFrameType => {
                println!("Received unknown frame type");
                break;
            }
            FrameType::ConnectionRequest => {
                println!("Received connection request");
                continue;
            }
            FrameType::ConnectionResponse => {
                println!("Received connection response");
                continue;
            }
            FrameType::PayloadTransfer => {}
            FrameType::BandwidthUpgradeNegotiation => {
                println!("Received bandwidth upgrade negotiation");
                continue;
            }
            FrameType::KeepAlive => {
                println!("Received keep alive");
                let keep_alive_frame = OfflineFrame {
                    version: Some(Version::V1 as i32),
                    v1: Some(V1Frame {
                        keep_alive: Some(KeepAliveFrame { ack: Some(true) }),
                        r#type: Some(FrameType::KeepAlive as i32),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                let mut num = sequence_number.lock().unwrap();
                send_packet(
                    stream,
                    encrypt_offline_frame(
                        keep_alive_frame,
                        keychain.server_key,
                        keychain.server_key_hmac,
                        *num,
                    ),
                );

                *num += 1;
                continue;
            }
            FrameType::Disconnection => {
                println!("Received disconnect");
                break;
            }
            FrameType::PairedKeyEncryption => {
                println!("Received paired key encryption");
                continue;
            }
        }

        // println!("received chunk {:?}", chunk_id);
        chunk_id += 1;

        let payload_frame = v1.payload_transfer.unwrap();

        let chunk = payload_frame.payload_chunk.as_ref().unwrap();

        if chunk_id == 0 {
            *framebuffer = Vec::<u8>::with_capacity(
                payload_frame
                    .clone()
                    .payload_header
                    .unwrap()
                    .total_size
                    .unwrap() as usize,
            );
        }

        if chunk.flags.unwrap() == 1 {
            break;
        } else {
            framebuffer.append(&mut chunk.body.as_ref().unwrap().to_vec());
            frametype =
                PayloadType::try_from(payload_frame.payload_header.unwrap().r#type.unwrap())
                    .unwrap();
        }
    }
    frametype
}

fn decrypt_offline_frame(
    secure_message: SecureMessage,
    decrypt_key: [u8; 32],
    hmac_key: [u8; 32],
) -> OfflineFrame {
    let hb = HeaderAndBody::decode(&secure_message.header_and_body[..]).unwrap();

    let iv: [u8; 16] = hb.header.iv.unwrap().try_into().unwrap();

    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut hmacc = HMAC::new(hmac_key);
    hmacc.update(secure_message.header_and_body.clone());
    let mac_res: [u8; 32] = hmacc.finalize();

    assert_eq!(secure_message.signature, mac_res.to_vec());

    let mut body_buf = hb.body.clone();

    let buf2 = Aes256CbcDec::new((&decrypt_key[..]).into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(body_buf.as_mut_slice())
        .unwrap();

    let d2d = DeviceToDeviceMessage::decode(buf2).unwrap();

    OfflineFrame::decode(d2d.message.unwrap().as_slice()).unwrap()
}

fn encrypt_offline_frame(
    offline_frame: OfflineFrame,
    encrypt_key: [u8; 32],
    hmac_key: [u8; 32],
    sequence_number: i32,
) -> Vec<u8> {
    let d2d = securegcm::DeviceToDeviceMessage {
        message: Some(offline_frame.encode_to_vec()),
        sequence_number: Some(sequence_number),
    };

    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut rng = ThreadRng::default();

    let iv: [u8; 16] = rng.gen();
    let plaintext = d2d.encode_to_vec();

    let mut buf: [u8; 1024] = [0u8; 1024];
    let buf2 = Aes256CbcEnc::new((&encrypt_key[..]).into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
        .unwrap();

    let md = GcmMetadata {
        r#type: securegcm::Type::DeviceToDeviceMessage as i32,
        version: Some(1),
    };

    let hb = HeaderAndBody {
        body: buf2.to_vec(),
        header: Header {
            encryption_scheme: EncScheme::Aes256Cbc as i32,
            signature_scheme: SigScheme::HmacSha256 as i32,
            iv: Some(iv.to_vec()),
            public_metadata: Some(md.encode_to_vec()),
            ..Default::default()
        },
    };

    let serialized_hb: Vec<u8> = hb.encode_to_vec();
    let mut hmacc = HMAC::new(hmac_key);
    hmacc.update(serialized_hb.clone());
    let mac_res: [u8; 32] = hmacc.finalize();

    let sec_msg = SecureMessage {
        header_and_body: serialized_hb,
        signature: mac_res.to_vec(),
    };

    sec_msg.encode_to_vec()
}

fn send_packet(stream: &mut TcpStream, packet: Vec<u8>) {
    let resp_len_buf: [u8; 4] = as_4u8buf(packet.len() as u32);
    // println!("sending buffer len: {:?}\n\n", packet.len());

    let mut buf = Vec::new();
    buf.extend_from_slice(&resp_len_buf);
    buf.extend_from_slice(&packet);

    stream.write(buf.as_slice()).unwrap();
}

fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf: [u8; 4] = [0; 4];
    stream.read(&mut len_buf).unwrap();
    let len: usize = as_u32_be(&len_buf) as usize;
    // println!("reading buffer len {}\n\n", len);

    let mut buf = vec![0; len];
    stream.read_exact(&mut buf).unwrap();
    buf
}

fn gen_sha256(input: Vec<u8>) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

fn gen_keychain(
    ukey2_client_finished: securegcm::Ukey2ClientFinished,
    server_init_serialized_data: Vec<u8>,
    client_init_serialized_data: Vec<u8>,
    secret_key: SecretKey,
) -> CryptoKeychain {
    let ukey2_client_key =
        GenericPublicKey::decode(&ukey2_client_finished.public_key.unwrap().to_vec()[..]).unwrap();
    use hkdf::Hkdf;
    use p256::ecdh::*;
    use sha2::{Digest, Sha256};

    let undecoded_key = ukey2_client_key.ec_p256_public_key.unwrap();
    let received_key_x: Vec<u8> = undecoded_key.x;
    let received_key_y = undecoded_key.y;

    let big_x = BigInt::from_signed_bytes_be(&received_key_x)
        .to_bytes_be()
        .1;
    let big_y = BigInt::from_signed_bytes_be(&received_key_y)
        .to_bytes_be()
        .1;

    let public_key: PublicKey =
        PublicKey::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &GenericArray::from_iter(big_x),
            &GenericArray::from_iter(big_y),
            false,
        ))
        .unwrap();

    let secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());

    let derived_secret = gen_sha256(secret.raw_secret_bytes().to_vec());

    let mut ukey_info: Vec<u8> = Vec::new();
    ukey_info.append(client_init_serialized_data.clone().as_mut());
    ukey_info.append(server_init_serialized_data.clone().as_mut());

    let mut auth_string: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some("UKEY2 v1 auth".as_bytes()), &derived_secret)
        .1
        .expand(&ukey_info, &mut auth_string)
        .unwrap();
    let mut next_secret: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some("UKEY2 v1 next".as_bytes()), &derived_secret)
        .1
        .expand(&ukey_info, &mut next_secret)
        .unwrap();

    let salt: [u8; 32] = [
        0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83, 0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09,
        0xB9, 0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3, 0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8,
        0x55, 0x10,
    ];

    let mut d2d_client_key: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some(&salt), &next_secret)
        .1
        .expand("client".as_bytes(), &mut d2d_client_key)
        .unwrap();
    let mut d2d_server_key: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some(&salt), &next_secret)
        .1
        .expand("server".as_bytes(), &mut d2d_server_key)
        .unwrap();

    let mut secure_message_hasher = Sha256::new();
    secure_message_hasher.update("SecureMessage".as_bytes());
    let secure_message_salt = secure_message_hasher.finalize();

    let mut client_key: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some(&secure_message_salt), &d2d_client_key)
        .1
        .expand("ENC:2".as_bytes(), &mut client_key)
        .unwrap();
    let mut client_key_hmac: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some(&secure_message_salt), &d2d_client_key)
        .1
        .expand("SIG:1".as_bytes(), &mut client_key_hmac)
        .unwrap();
    let mut server_key: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some(&secure_message_salt), &d2d_server_key)
        .1
        .expand("ENC:2".as_bytes(), &mut server_key)
        .unwrap();
    let mut server_key_hmac: [u8; 32] = [0; 32];
    Hkdf::<Sha256>::extract(Some(&secure_message_salt), &d2d_server_key)
        .1
        .expand("SIG:1".as_bytes(), &mut server_key_hmac)
        .unwrap();

    CryptoKeychain {
        client_key,
        client_key_hmac,
        server_key,
        server_key_hmac,
    }
}

fn generate_endpoint_id() -> [u8; 4] {
    let mut id: [u8; 4] = [0, 0, 0, 0];
    let alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes();

    let mut rng = rand::thread_rng();

    for i in 0..4 {
        id[i] = alphabet[rng.gen_range(0..alphabet.len())] as u8;
    }
    id
}

pub fn generate_txt_record(device_name: String, device_type: DeviceType) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let mut endpoint_info: Vec<u8> = Vec::new();

    // 1 byte: Version(3 bits)|Visibility(1 bit)|Device Type(3 bits)|Reserved(1 bits)
    endpoint_info.push((device_type as u8) << 1);
    let mut rng = rand::thread_rng();
    // 16 bytes: unknown random bytes
    for _ in 0..16 {
        endpoint_info.push(rng.gen_range(0..255) as u8);
    }

    // Device name in UTF-8 prefixed with 1-byte length
    endpoint_info.push((device_name.as_bytes().len()) as u8);
    let mut utf_buffer: [u8; 4] = [0; 4];
    for ch in device_name.chars() {
        let utf8 = ch.encode_utf8(&mut utf_buffer);
        for ch_utf in utf8.as_bytes() {
            endpoint_info.push(ch_utf.clone());
        }
    }

    general_purpose::URL_SAFE_NO_PAD.encode(&endpoint_info)
}

pub fn generate_name() -> String {
    use base64::{engine::general_purpose, Engine as _};

    let endpoint_id = generate_endpoint_id();

    let name_bytes: Vec<u8> = vec![
        0x23, // PCP
        endpoint_id[0],
        endpoint_id[1],
        endpoint_id[2],
        endpoint_id[3],
        0xFC,
        0x9F,
        0x5E, // Service ID hash
        0,
        0,
    ];

    general_purpose::URL_SAFE_NO_PAD.encode(&name_bytes)
}

#[allow(dead_code)]
pub enum DeviceType {
    UNKNOWN = 0,
    PHONE = 1,
    TABLET = 2,
    LAPTOP = 3,
}

from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool
from google.protobuf import message_factory


file_proto = descriptor_pb2.FileDescriptorProto()
file_proto.name = "adb_host.proto"
file_proto.package = "adb.proto"
file_proto.syntax = "proto3"

state = file_proto.enum_type.add()
state.name = "ConnectionState"
for name, number in (
    ("ANY", 0),
    ("CONNECTING", 1),
    ("AUTHORIZING", 2),
    ("UNAUTHORIZED", 3),
    ("NOPERMISSION", 4),
    ("DETACHED", 5),
    ("OFFLINE", 6),
    ("BOOTLOADER", 7),
    ("DEVICE", 8),
    ("HOST", 9),
    ("RECOVERY", 10),
    ("SIDELOAD", 11),
    ("RESCUE", 12),
):
    value = state.value.add()
    value.name = name
    value.number = number

connection_type = file_proto.enum_type.add()
connection_type.name = "ConnectionType"
for name, number in (("UNKNOWN", 0), ("USB", 1), ("SOCKET", 2)):
    value = connection_type.value.add()
    value.name = name
    value.number = number

device = file_proto.message_type.add()
device.name = "Device"
fields = (
    ("serial", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING, None),
    ("state", 2, descriptor_pb2.FieldDescriptorProto.TYPE_ENUM, ".adb.proto.ConnectionState"),
    ("bus_address", 3, descriptor_pb2.FieldDescriptorProto.TYPE_STRING, None),
    ("product", 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING, None),
    ("model", 5, descriptor_pb2.FieldDescriptorProto.TYPE_STRING, None),
    ("device", 6, descriptor_pb2.FieldDescriptorProto.TYPE_STRING, None),
    (
        "connection_type",
        7,
        descriptor_pb2.FieldDescriptorProto.TYPE_ENUM,
        ".adb.proto.ConnectionType",
    ),
    ("negotiated_speed", 8, descriptor_pb2.FieldDescriptorProto.TYPE_INT64, None),
    ("max_speed", 9, descriptor_pb2.FieldDescriptorProto.TYPE_INT64, None),
    ("transport_id", 10, descriptor_pb2.FieldDescriptorProto.TYPE_INT64, None),
)
for name, number, field_type, type_name in fields:
    field = device.field.add()
    field.name = name
    field.number = number
    field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    field.type = field_type
    if type_name is not None:
        field.type_name = type_name

devices = file_proto.message_type.add()
devices.name = "Devices"
field = devices.field.add()
field.name = "device"
field.number = 1
field.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
field.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
field.type_name = ".adb.proto.Device"

DESCRIPTOR = descriptor_pool.Default().AddSerializedFile(file_proto.SerializeToString())
Device = message_factory.GetMessageClass(DESCRIPTOR.message_types_by_name["Device"])
Devices = message_factory.GetMessageClass(DESCRIPTOR.message_types_by_name["Devices"])

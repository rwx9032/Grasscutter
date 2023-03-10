// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: LunaRiteHintStatusType.proto

package emu.grasscutter.net.proto;

public final class LunaRiteHintStatusTypeOuterClass {
  private LunaRiteHintStatusTypeOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  /**
   * <pre>
   * Name: OJDHIEBPOKL
   * </pre>
   *
   * Protobuf enum {@code LunaRiteHintStatusType}
   */
  public enum LunaRiteHintStatusType
      implements com.google.protobuf.ProtocolMessageEnum {
    /**
     * <code>LUNA_RITE_HINT_STATUS_DEFAULT = 0;</code>
     */
    LUNA_RITE_HINT_STATUS_DEFAULT(0),
    /**
     * <code>LUNA_RITE_HINT_STATUS_NO_COUNT = 1;</code>
     */
    LUNA_RITE_HINT_STATUS_NO_COUNT(1),
    /**
     * <code>LUNA_RITE_HINT_STATUS_FINISH = 2;</code>
     */
    LUNA_RITE_HINT_STATUS_FINISH(2),
    UNRECOGNIZED(-1),
    ;

    /**
     * <code>LUNA_RITE_HINT_STATUS_DEFAULT = 0;</code>
     */
    public static final int LUNA_RITE_HINT_STATUS_DEFAULT_VALUE = 0;
    /**
     * <code>LUNA_RITE_HINT_STATUS_NO_COUNT = 1;</code>
     */
    public static final int LUNA_RITE_HINT_STATUS_NO_COUNT_VALUE = 1;
    /**
     * <code>LUNA_RITE_HINT_STATUS_FINISH = 2;</code>
     */
    public static final int LUNA_RITE_HINT_STATUS_FINISH_VALUE = 2;


    public final int getNumber() {
      if (this == UNRECOGNIZED) {
        throw new java.lang.IllegalArgumentException(
            "Can't get the number of an unknown enum value.");
      }
      return value;
    }

    /**
     * @param value The numeric wire value of the corresponding enum entry.
     * @return The enum associated with the given numeric wire value.
     * @deprecated Use {@link #forNumber(int)} instead.
     */
    @java.lang.Deprecated
    public static LunaRiteHintStatusType valueOf(int value) {
      return forNumber(value);
    }

    /**
     * @param value The numeric wire value of the corresponding enum entry.
     * @return The enum associated with the given numeric wire value.
     */
    public static LunaRiteHintStatusType forNumber(int value) {
      switch (value) {
        case 0: return LUNA_RITE_HINT_STATUS_DEFAULT;
        case 1: return LUNA_RITE_HINT_STATUS_NO_COUNT;
        case 2: return LUNA_RITE_HINT_STATUS_FINISH;
        default: return null;
      }
    }

    public static com.google.protobuf.Internal.EnumLiteMap<LunaRiteHintStatusType>
        internalGetValueMap() {
      return internalValueMap;
    }
    private static final com.google.protobuf.Internal.EnumLiteMap<
        LunaRiteHintStatusType> internalValueMap =
          new com.google.protobuf.Internal.EnumLiteMap<LunaRiteHintStatusType>() {
            public LunaRiteHintStatusType findValueByNumber(int number) {
              return LunaRiteHintStatusType.forNumber(number);
            }
          };

    public final com.google.protobuf.Descriptors.EnumValueDescriptor
        getValueDescriptor() {
      if (this == UNRECOGNIZED) {
        throw new java.lang.IllegalStateException(
            "Can't get the descriptor of an unrecognized enum value.");
      }
      return getDescriptor().getValues().get(ordinal());
    }
    public final com.google.protobuf.Descriptors.EnumDescriptor
        getDescriptorForType() {
      return getDescriptor();
    }
    public static final com.google.protobuf.Descriptors.EnumDescriptor
        getDescriptor() {
      return emu.grasscutter.net.proto.LunaRiteHintStatusTypeOuterClass.getDescriptor().getEnumTypes().get(0);
    }

    private static final LunaRiteHintStatusType[] VALUES = values();

    public static LunaRiteHintStatusType valueOf(
        com.google.protobuf.Descriptors.EnumValueDescriptor desc) {
      if (desc.getType() != getDescriptor()) {
        throw new java.lang.IllegalArgumentException(
          "EnumValueDescriptor is not for this type.");
      }
      if (desc.getIndex() == -1) {
        return UNRECOGNIZED;
      }
      return VALUES[desc.getIndex()];
    }

    private final int value;

    private LunaRiteHintStatusType(int value) {
      this.value = value;
    }

    // @@protoc_insertion_point(enum_scope:LunaRiteHintStatusType)
  }


  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\034LunaRiteHintStatusType.proto*\201\001\n\026LunaR" +
      "iteHintStatusType\022!\n\035LUNA_RITE_HINT_STAT" +
      "US_DEFAULT\020\000\022\"\n\036LUNA_RITE_HINT_STATUS_NO" +
      "_COUNT\020\001\022 \n\034LUNA_RITE_HINT_STATUS_FINISH" +
      "\020\002B\033\n\031emu.grasscutter.net.protob\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
  }

  // @@protoc_insertion_point(outer_class_scope)
}

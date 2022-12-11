// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: ExitSceneWeatherAreaNotify.proto

package emu.grasscutter.net.proto;

public final class ExitSceneWeatherAreaNotifyOuterClass {
  private ExitSceneWeatherAreaNotifyOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface ExitSceneWeatherAreaNotifyOrBuilder extends
      // @@protoc_insertion_point(interface_extends:ExitSceneWeatherAreaNotify)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>uint32 weather_gadget_id = 13;</code>
     * @return The weatherGadgetId.
     */
    int getWeatherGadgetId();
  }
  /**
   * <pre>
   * enum CmdId {
   *   option allow_alias = true;
   *   NONE = 0;
   *   CMD_ID = 211;
   *   ENET_CHANNEL_ID = 0;
   *   ENET_IS_RELIABLE = 1;
   *   IS_ALLOW_CLIENT = 1;
   * }
   * </pre>
   *
   * Protobuf type {@code ExitSceneWeatherAreaNotify}
   */
  public static final class ExitSceneWeatherAreaNotify extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:ExitSceneWeatherAreaNotify)
      ExitSceneWeatherAreaNotifyOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use ExitSceneWeatherAreaNotify.newBuilder() to construct.
    private ExitSceneWeatherAreaNotify(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private ExitSceneWeatherAreaNotify() {
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new ExitSceneWeatherAreaNotify();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private ExitSceneWeatherAreaNotify(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            case 104: {

              weatherGadgetId_ = input.readUInt32();
              break;
            }
            default: {
              if (!parseUnknownField(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.internal_static_ExitSceneWeatherAreaNotify_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.internal_static_ExitSceneWeatherAreaNotify_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify.class, emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify.Builder.class);
    }

    public static final int WEATHER_GADGET_ID_FIELD_NUMBER = 13;
    private int weatherGadgetId_;
    /**
     * <code>uint32 weather_gadget_id = 13;</code>
     * @return The weatherGadgetId.
     */
    @java.lang.Override
    public int getWeatherGadgetId() {
      return weatherGadgetId_;
    }

    private byte memoizedIsInitialized = -1;
    @java.lang.Override
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    @java.lang.Override
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (weatherGadgetId_ != 0) {
        output.writeUInt32(13, weatherGadgetId_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (weatherGadgetId_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(13, weatherGadgetId_);
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify other = (emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify) obj;

      if (getWeatherGadgetId()
          != other.getWeatherGadgetId()) return false;
      if (!unknownFields.equals(other.unknownFields)) return false;
      return true;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      hash = (37 * hash) + WEATHER_GADGET_ID_FIELD_NUMBER;
      hash = (53 * hash) + getWeatherGadgetId();
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    @java.lang.Override
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    @java.lang.Override
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * <pre>
     * enum CmdId {
     *   option allow_alias = true;
     *   NONE = 0;
     *   CMD_ID = 211;
     *   ENET_CHANNEL_ID = 0;
     *   ENET_IS_RELIABLE = 1;
     *   IS_ALLOW_CLIENT = 1;
     * }
     * </pre>
     *
     * Protobuf type {@code ExitSceneWeatherAreaNotify}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:ExitSceneWeatherAreaNotify)
        emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotifyOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.internal_static_ExitSceneWeatherAreaNotify_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.internal_static_ExitSceneWeatherAreaNotify_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify.class, emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        weatherGadgetId_ = 0;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.internal_static_ExitSceneWeatherAreaNotify_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify build() {
        emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify buildPartial() {
        emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify result = new emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify(this);
        result.weatherGadgetId_ = weatherGadgetId_;
        onBuilt();
        return result;
      }

      @java.lang.Override
      public Builder clone() {
        return super.clone();
      }
      @java.lang.Override
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.setField(field, value);
      }
      @java.lang.Override
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return super.clearField(field);
      }
      @java.lang.Override
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return super.clearOneof(oneof);
      }
      @java.lang.Override
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return super.setRepeatedField(field, index, value);
      }
      @java.lang.Override
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.addRepeatedField(field, value);
      }
      @java.lang.Override
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify) {
          return mergeFrom((emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify other) {
        if (other == emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify.getDefaultInstance()) return this;
        if (other.getWeatherGadgetId() != 0) {
          setWeatherGadgetId(other.getWeatherGadgetId());
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      @java.lang.Override
      public final boolean isInitialized() {
        return true;
      }

      @java.lang.Override
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private int weatherGadgetId_ ;
      /**
       * <code>uint32 weather_gadget_id = 13;</code>
       * @return The weatherGadgetId.
       */
      @java.lang.Override
      public int getWeatherGadgetId() {
        return weatherGadgetId_;
      }
      /**
       * <code>uint32 weather_gadget_id = 13;</code>
       * @param value The weatherGadgetId to set.
       * @return This builder for chaining.
       */
      public Builder setWeatherGadgetId(int value) {
        
        weatherGadgetId_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 weather_gadget_id = 13;</code>
       * @return This builder for chaining.
       */
      public Builder clearWeatherGadgetId() {
        
        weatherGadgetId_ = 0;
        onChanged();
        return this;
      }
      @java.lang.Override
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFields(unknownFields);
      }

      @java.lang.Override
      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }


      // @@protoc_insertion_point(builder_scope:ExitSceneWeatherAreaNotify)
    }

    // @@protoc_insertion_point(class_scope:ExitSceneWeatherAreaNotify)
    private static final emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify();
    }

    public static emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<ExitSceneWeatherAreaNotify>
        PARSER = new com.google.protobuf.AbstractParser<ExitSceneWeatherAreaNotify>() {
      @java.lang.Override
      public ExitSceneWeatherAreaNotify parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new ExitSceneWeatherAreaNotify(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<ExitSceneWeatherAreaNotify> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<ExitSceneWeatherAreaNotify> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.ExitSceneWeatherAreaNotifyOuterClass.ExitSceneWeatherAreaNotify getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_ExitSceneWeatherAreaNotify_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_ExitSceneWeatherAreaNotify_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n ExitSceneWeatherAreaNotify.proto\"7\n\032Ex" +
      "itSceneWeatherAreaNotify\022\031\n\021weather_gadg" +
      "et_id\030\r \001(\rB\033\n\031emu.grasscutter.net.proto" +
      "b\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_ExitSceneWeatherAreaNotify_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_ExitSceneWeatherAreaNotify_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_ExitSceneWeatherAreaNotify_descriptor,
        new java.lang.String[] { "WeatherGadgetId", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}

// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: StartBuoyantCombatGalleryRsp.proto

package emu.grasscutter.net.proto;

public final class StartBuoyantCombatGalleryRspOuterClass {
  private StartBuoyantCombatGalleryRspOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface StartBuoyantCombatGalleryRspOrBuilder extends
      // @@protoc_insertion_point(interface_extends:StartBuoyantCombatGalleryRsp)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>uint32 gallery_level = 6;</code>
     * @return The galleryLevel.
     */
    int getGalleryLevel();

    /**
     * <code>int32 retcode = 5;</code>
     * @return The retcode.
     */
    int getRetcode();

    /**
     * <code>uint32 gallery_id = 12;</code>
     * @return The galleryId.
     */
    int getGalleryId();
  }
  /**
   * <pre>
   * enum CmdId {
   *   option allow_alias = true;
   *   NONE = 0;
   *   CMD_ID = 8969;
   *   ENET_CHANNEL_ID = 0;
   *   ENET_IS_RELIABLE = 1;
   * }
   * </pre>
   *
   * Protobuf type {@code StartBuoyantCombatGalleryRsp}
   */
  public static final class StartBuoyantCombatGalleryRsp extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:StartBuoyantCombatGalleryRsp)
      StartBuoyantCombatGalleryRspOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use StartBuoyantCombatGalleryRsp.newBuilder() to construct.
    private StartBuoyantCombatGalleryRsp(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private StartBuoyantCombatGalleryRsp() {
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new StartBuoyantCombatGalleryRsp();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private StartBuoyantCombatGalleryRsp(
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
            case 40: {

              retcode_ = input.readInt32();
              break;
            }
            case 48: {

              galleryLevel_ = input.readUInt32();
              break;
            }
            case 96: {

              galleryId_ = input.readUInt32();
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
      return emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.internal_static_StartBuoyantCombatGalleryRsp_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.internal_static_StartBuoyantCombatGalleryRsp_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp.class, emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp.Builder.class);
    }

    public static final int GALLERY_LEVEL_FIELD_NUMBER = 6;
    private int galleryLevel_;
    /**
     * <code>uint32 gallery_level = 6;</code>
     * @return The galleryLevel.
     */
    @java.lang.Override
    public int getGalleryLevel() {
      return galleryLevel_;
    }

    public static final int RETCODE_FIELD_NUMBER = 5;
    private int retcode_;
    /**
     * <code>int32 retcode = 5;</code>
     * @return The retcode.
     */
    @java.lang.Override
    public int getRetcode() {
      return retcode_;
    }

    public static final int GALLERY_ID_FIELD_NUMBER = 12;
    private int galleryId_;
    /**
     * <code>uint32 gallery_id = 12;</code>
     * @return The galleryId.
     */
    @java.lang.Override
    public int getGalleryId() {
      return galleryId_;
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
      if (retcode_ != 0) {
        output.writeInt32(5, retcode_);
      }
      if (galleryLevel_ != 0) {
        output.writeUInt32(6, galleryLevel_);
      }
      if (galleryId_ != 0) {
        output.writeUInt32(12, galleryId_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (retcode_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeInt32Size(5, retcode_);
      }
      if (galleryLevel_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(6, galleryLevel_);
      }
      if (galleryId_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(12, galleryId_);
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
      if (!(obj instanceof emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp other = (emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp) obj;

      if (getGalleryLevel()
          != other.getGalleryLevel()) return false;
      if (getRetcode()
          != other.getRetcode()) return false;
      if (getGalleryId()
          != other.getGalleryId()) return false;
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
      hash = (37 * hash) + GALLERY_LEVEL_FIELD_NUMBER;
      hash = (53 * hash) + getGalleryLevel();
      hash = (37 * hash) + RETCODE_FIELD_NUMBER;
      hash = (53 * hash) + getRetcode();
      hash = (37 * hash) + GALLERY_ID_FIELD_NUMBER;
      hash = (53 * hash) + getGalleryId();
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parseFrom(
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
    public static Builder newBuilder(emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp prototype) {
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
     *   CMD_ID = 8969;
     *   ENET_CHANNEL_ID = 0;
     *   ENET_IS_RELIABLE = 1;
     * }
     * </pre>
     *
     * Protobuf type {@code StartBuoyantCombatGalleryRsp}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:StartBuoyantCombatGalleryRsp)
        emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRspOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.internal_static_StartBuoyantCombatGalleryRsp_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.internal_static_StartBuoyantCombatGalleryRsp_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp.class, emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp.newBuilder()
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
        galleryLevel_ = 0;

        retcode_ = 0;

        galleryId_ = 0;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.internal_static_StartBuoyantCombatGalleryRsp_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp build() {
        emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp buildPartial() {
        emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp result = new emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp(this);
        result.galleryLevel_ = galleryLevel_;
        result.retcode_ = retcode_;
        result.galleryId_ = galleryId_;
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
        if (other instanceof emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp) {
          return mergeFrom((emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp other) {
        if (other == emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp.getDefaultInstance()) return this;
        if (other.getGalleryLevel() != 0) {
          setGalleryLevel(other.getGalleryLevel());
        }
        if (other.getRetcode() != 0) {
          setRetcode(other.getRetcode());
        }
        if (other.getGalleryId() != 0) {
          setGalleryId(other.getGalleryId());
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
        emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private int galleryLevel_ ;
      /**
       * <code>uint32 gallery_level = 6;</code>
       * @return The galleryLevel.
       */
      @java.lang.Override
      public int getGalleryLevel() {
        return galleryLevel_;
      }
      /**
       * <code>uint32 gallery_level = 6;</code>
       * @param value The galleryLevel to set.
       * @return This builder for chaining.
       */
      public Builder setGalleryLevel(int value) {
        
        galleryLevel_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 gallery_level = 6;</code>
       * @return This builder for chaining.
       */
      public Builder clearGalleryLevel() {
        
        galleryLevel_ = 0;
        onChanged();
        return this;
      }

      private int retcode_ ;
      /**
       * <code>int32 retcode = 5;</code>
       * @return The retcode.
       */
      @java.lang.Override
      public int getRetcode() {
        return retcode_;
      }
      /**
       * <code>int32 retcode = 5;</code>
       * @param value The retcode to set.
       * @return This builder for chaining.
       */
      public Builder setRetcode(int value) {
        
        retcode_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>int32 retcode = 5;</code>
       * @return This builder for chaining.
       */
      public Builder clearRetcode() {
        
        retcode_ = 0;
        onChanged();
        return this;
      }

      private int galleryId_ ;
      /**
       * <code>uint32 gallery_id = 12;</code>
       * @return The galleryId.
       */
      @java.lang.Override
      public int getGalleryId() {
        return galleryId_;
      }
      /**
       * <code>uint32 gallery_id = 12;</code>
       * @param value The galleryId to set.
       * @return This builder for chaining.
       */
      public Builder setGalleryId(int value) {
        
        galleryId_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 gallery_id = 12;</code>
       * @return This builder for chaining.
       */
      public Builder clearGalleryId() {
        
        galleryId_ = 0;
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


      // @@protoc_insertion_point(builder_scope:StartBuoyantCombatGalleryRsp)
    }

    // @@protoc_insertion_point(class_scope:StartBuoyantCombatGalleryRsp)
    private static final emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp();
    }

    public static emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<StartBuoyantCombatGalleryRsp>
        PARSER = new com.google.protobuf.AbstractParser<StartBuoyantCombatGalleryRsp>() {
      @java.lang.Override
      public StartBuoyantCombatGalleryRsp parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new StartBuoyantCombatGalleryRsp(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<StartBuoyantCombatGalleryRsp> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<StartBuoyantCombatGalleryRsp> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.StartBuoyantCombatGalleryRspOuterClass.StartBuoyantCombatGalleryRsp getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_StartBuoyantCombatGalleryRsp_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_StartBuoyantCombatGalleryRsp_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\"StartBuoyantCombatGalleryRsp.proto\"Z\n\034" +
      "StartBuoyantCombatGalleryRsp\022\025\n\rgallery_" +
      "level\030\006 \001(\r\022\017\n\007retcode\030\005 \001(\005\022\022\n\ngallery_" +
      "id\030\014 \001(\rB\033\n\031emu.grasscutter.net.protob\006p" +
      "roto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_StartBuoyantCombatGalleryRsp_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_StartBuoyantCombatGalleryRsp_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_StartBuoyantCombatGalleryRsp_descriptor,
        new java.lang.String[] { "GalleryLevel", "Retcode", "GalleryId", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}

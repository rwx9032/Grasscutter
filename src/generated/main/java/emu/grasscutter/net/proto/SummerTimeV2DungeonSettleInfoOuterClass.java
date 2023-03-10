// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: SummerTimeV2DungeonSettleInfo.proto

package emu.grasscutter.net.proto;

public final class SummerTimeV2DungeonSettleInfoOuterClass {
  private SummerTimeV2DungeonSettleInfoOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface SummerTimeV2DungeonSettleInfoOrBuilder extends
      // @@protoc_insertion_point(interface_extends:SummerTimeV2DungeonSettleInfo)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>bool is_success = 5;</code>
     * @return The isSuccess.
     */
    boolean getIsSuccess();

    /**
     * <code>uint32 IMHBJJAIBFJ = 12;</code>
     * @return The iMHBJJAIBFJ.
     */
    int getIMHBJJAIBFJ();

    /**
     * <code>uint32 JHEBGEDHMLB = 3;</code>
     * @return The jHEBGEDHMLB.
     */
    int getJHEBGEDHMLB();
  }
  /**
   * <pre>
   * Name: IJIFIANJEKJ
   * </pre>
   *
   * Protobuf type {@code SummerTimeV2DungeonSettleInfo}
   */
  public static final class SummerTimeV2DungeonSettleInfo extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:SummerTimeV2DungeonSettleInfo)
      SummerTimeV2DungeonSettleInfoOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use SummerTimeV2DungeonSettleInfo.newBuilder() to construct.
    private SummerTimeV2DungeonSettleInfo(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private SummerTimeV2DungeonSettleInfo() {
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new SummerTimeV2DungeonSettleInfo();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private SummerTimeV2DungeonSettleInfo(
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
            case 24: {

              jHEBGEDHMLB_ = input.readUInt32();
              break;
            }
            case 40: {

              isSuccess_ = input.readBool();
              break;
            }
            case 96: {

              iMHBJJAIBFJ_ = input.readUInt32();
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
      return emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.internal_static_SummerTimeV2DungeonSettleInfo_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.internal_static_SummerTimeV2DungeonSettleInfo_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo.class, emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo.Builder.class);
    }

    public static final int IS_SUCCESS_FIELD_NUMBER = 5;
    private boolean isSuccess_;
    /**
     * <code>bool is_success = 5;</code>
     * @return The isSuccess.
     */
    @java.lang.Override
    public boolean getIsSuccess() {
      return isSuccess_;
    }

    public static final int IMHBJJAIBFJ_FIELD_NUMBER = 12;
    private int iMHBJJAIBFJ_;
    /**
     * <code>uint32 IMHBJJAIBFJ = 12;</code>
     * @return The iMHBJJAIBFJ.
     */
    @java.lang.Override
    public int getIMHBJJAIBFJ() {
      return iMHBJJAIBFJ_;
    }

    public static final int JHEBGEDHMLB_FIELD_NUMBER = 3;
    private int jHEBGEDHMLB_;
    /**
     * <code>uint32 JHEBGEDHMLB = 3;</code>
     * @return The jHEBGEDHMLB.
     */
    @java.lang.Override
    public int getJHEBGEDHMLB() {
      return jHEBGEDHMLB_;
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
      if (jHEBGEDHMLB_ != 0) {
        output.writeUInt32(3, jHEBGEDHMLB_);
      }
      if (isSuccess_ != false) {
        output.writeBool(5, isSuccess_);
      }
      if (iMHBJJAIBFJ_ != 0) {
        output.writeUInt32(12, iMHBJJAIBFJ_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (jHEBGEDHMLB_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(3, jHEBGEDHMLB_);
      }
      if (isSuccess_ != false) {
        size += com.google.protobuf.CodedOutputStream
          .computeBoolSize(5, isSuccess_);
      }
      if (iMHBJJAIBFJ_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(12, iMHBJJAIBFJ_);
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
      if (!(obj instanceof emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo other = (emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo) obj;

      if (getIsSuccess()
          != other.getIsSuccess()) return false;
      if (getIMHBJJAIBFJ()
          != other.getIMHBJJAIBFJ()) return false;
      if (getJHEBGEDHMLB()
          != other.getJHEBGEDHMLB()) return false;
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
      hash = (37 * hash) + IS_SUCCESS_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashBoolean(
          getIsSuccess());
      hash = (37 * hash) + IMHBJJAIBFJ_FIELD_NUMBER;
      hash = (53 * hash) + getIMHBJJAIBFJ();
      hash = (37 * hash) + JHEBGEDHMLB_FIELD_NUMBER;
      hash = (53 * hash) + getJHEBGEDHMLB();
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parseFrom(
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
    public static Builder newBuilder(emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo prototype) {
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
     * Name: IJIFIANJEKJ
     * </pre>
     *
     * Protobuf type {@code SummerTimeV2DungeonSettleInfo}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:SummerTimeV2DungeonSettleInfo)
        emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfoOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.internal_static_SummerTimeV2DungeonSettleInfo_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.internal_static_SummerTimeV2DungeonSettleInfo_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo.class, emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo.newBuilder()
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
        isSuccess_ = false;

        iMHBJJAIBFJ_ = 0;

        jHEBGEDHMLB_ = 0;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.internal_static_SummerTimeV2DungeonSettleInfo_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo build() {
        emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo buildPartial() {
        emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo result = new emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo(this);
        result.isSuccess_ = isSuccess_;
        result.iMHBJJAIBFJ_ = iMHBJJAIBFJ_;
        result.jHEBGEDHMLB_ = jHEBGEDHMLB_;
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
        if (other instanceof emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo) {
          return mergeFrom((emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo other) {
        if (other == emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo.getDefaultInstance()) return this;
        if (other.getIsSuccess() != false) {
          setIsSuccess(other.getIsSuccess());
        }
        if (other.getIMHBJJAIBFJ() != 0) {
          setIMHBJJAIBFJ(other.getIMHBJJAIBFJ());
        }
        if (other.getJHEBGEDHMLB() != 0) {
          setJHEBGEDHMLB(other.getJHEBGEDHMLB());
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
        emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private boolean isSuccess_ ;
      /**
       * <code>bool is_success = 5;</code>
       * @return The isSuccess.
       */
      @java.lang.Override
      public boolean getIsSuccess() {
        return isSuccess_;
      }
      /**
       * <code>bool is_success = 5;</code>
       * @param value The isSuccess to set.
       * @return This builder for chaining.
       */
      public Builder setIsSuccess(boolean value) {
        
        isSuccess_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>bool is_success = 5;</code>
       * @return This builder for chaining.
       */
      public Builder clearIsSuccess() {
        
        isSuccess_ = false;
        onChanged();
        return this;
      }

      private int iMHBJJAIBFJ_ ;
      /**
       * <code>uint32 IMHBJJAIBFJ = 12;</code>
       * @return The iMHBJJAIBFJ.
       */
      @java.lang.Override
      public int getIMHBJJAIBFJ() {
        return iMHBJJAIBFJ_;
      }
      /**
       * <code>uint32 IMHBJJAIBFJ = 12;</code>
       * @param value The iMHBJJAIBFJ to set.
       * @return This builder for chaining.
       */
      public Builder setIMHBJJAIBFJ(int value) {
        
        iMHBJJAIBFJ_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 IMHBJJAIBFJ = 12;</code>
       * @return This builder for chaining.
       */
      public Builder clearIMHBJJAIBFJ() {
        
        iMHBJJAIBFJ_ = 0;
        onChanged();
        return this;
      }

      private int jHEBGEDHMLB_ ;
      /**
       * <code>uint32 JHEBGEDHMLB = 3;</code>
       * @return The jHEBGEDHMLB.
       */
      @java.lang.Override
      public int getJHEBGEDHMLB() {
        return jHEBGEDHMLB_;
      }
      /**
       * <code>uint32 JHEBGEDHMLB = 3;</code>
       * @param value The jHEBGEDHMLB to set.
       * @return This builder for chaining.
       */
      public Builder setJHEBGEDHMLB(int value) {
        
        jHEBGEDHMLB_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 JHEBGEDHMLB = 3;</code>
       * @return This builder for chaining.
       */
      public Builder clearJHEBGEDHMLB() {
        
        jHEBGEDHMLB_ = 0;
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


      // @@protoc_insertion_point(builder_scope:SummerTimeV2DungeonSettleInfo)
    }

    // @@protoc_insertion_point(class_scope:SummerTimeV2DungeonSettleInfo)
    private static final emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo();
    }

    public static emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<SummerTimeV2DungeonSettleInfo>
        PARSER = new com.google.protobuf.AbstractParser<SummerTimeV2DungeonSettleInfo>() {
      @java.lang.Override
      public SummerTimeV2DungeonSettleInfo parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new SummerTimeV2DungeonSettleInfo(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<SummerTimeV2DungeonSettleInfo> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<SummerTimeV2DungeonSettleInfo> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.SummerTimeV2DungeonSettleInfoOuterClass.SummerTimeV2DungeonSettleInfo getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_SummerTimeV2DungeonSettleInfo_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_SummerTimeV2DungeonSettleInfo_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n#SummerTimeV2DungeonSettleInfo.proto\"]\n" +
      "\035SummerTimeV2DungeonSettleInfo\022\022\n\nis_suc" +
      "cess\030\005 \001(\010\022\023\n\013IMHBJJAIBFJ\030\014 \001(\r\022\023\n\013JHEBG" +
      "EDHMLB\030\003 \001(\rB\033\n\031emu.grasscutter.net.prot" +
      "ob\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_SummerTimeV2DungeonSettleInfo_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_SummerTimeV2DungeonSettleInfo_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_SummerTimeV2DungeonSettleInfo_descriptor,
        new java.lang.String[] { "IsSuccess", "IMHBJJAIBFJ", "JHEBGEDHMLB", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}

// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: GetAllH5ActivityInfoRsp.proto

package emu.grasscutter.net.proto;

public final class GetAllH5ActivityInfoRspOuterClass {
  private GetAllH5ActivityInfoRspOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface GetAllH5ActivityInfoRspOrBuilder extends
      // @@protoc_insertion_point(interface_extends:GetAllH5ActivityInfoRsp)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>uint32 client_red_dot_timestamp = 3;</code>
     * @return The clientRedDotTimestamp.
     */
    int getClientRedDotTimestamp();

    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    java.util.List<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo> 
        getH5ActivityInfoListList();
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo getH5ActivityInfoList(int index);
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    int getH5ActivityInfoListCount();
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    java.util.List<? extends emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder> 
        getH5ActivityInfoListOrBuilderList();
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder getH5ActivityInfoListOrBuilder(
        int index);

    /**
     * <code>int32 retcode = 14;</code>
     * @return The retcode.
     */
    int getRetcode();
  }
  /**
   * <pre>
   * enum CmdId {
   *   option allow_alias = true;
   *   NONE = 0;
   *   CMD_ID = 5692;
   *   ENET_CHANNEL_ID = 0;
   *   ENET_IS_RELIABLE = 1;
   * }
   * </pre>
   *
   * Protobuf type {@code GetAllH5ActivityInfoRsp}
   */
  public static final class GetAllH5ActivityInfoRsp extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:GetAllH5ActivityInfoRsp)
      GetAllH5ActivityInfoRspOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use GetAllH5ActivityInfoRsp.newBuilder() to construct.
    private GetAllH5ActivityInfoRsp(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private GetAllH5ActivityInfoRsp() {
      h5ActivityInfoList_ = java.util.Collections.emptyList();
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new GetAllH5ActivityInfoRsp();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private GetAllH5ActivityInfoRsp(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      int mutable_bitField0_ = 0;
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

              clientRedDotTimestamp_ = input.readUInt32();
              break;
            }
            case 42: {
              if (!((mutable_bitField0_ & 0x00000001) != 0)) {
                h5ActivityInfoList_ = new java.util.ArrayList<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo>();
                mutable_bitField0_ |= 0x00000001;
              }
              h5ActivityInfoList_.add(
                  input.readMessage(emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.parser(), extensionRegistry));
              break;
            }
            case 112: {

              retcode_ = input.readInt32();
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
        if (((mutable_bitField0_ & 0x00000001) != 0)) {
          h5ActivityInfoList_ = java.util.Collections.unmodifiableList(h5ActivityInfoList_);
        }
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.internal_static_GetAllH5ActivityInfoRsp_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.internal_static_GetAllH5ActivityInfoRsp_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp.class, emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp.Builder.class);
    }

    public static final int CLIENT_RED_DOT_TIMESTAMP_FIELD_NUMBER = 3;
    private int clientRedDotTimestamp_;
    /**
     * <code>uint32 client_red_dot_timestamp = 3;</code>
     * @return The clientRedDotTimestamp.
     */
    @java.lang.Override
    public int getClientRedDotTimestamp() {
      return clientRedDotTimestamp_;
    }

    public static final int H5_ACTIVITY_INFO_LIST_FIELD_NUMBER = 5;
    private java.util.List<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo> h5ActivityInfoList_;
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    @java.lang.Override
    public java.util.List<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo> getH5ActivityInfoListList() {
      return h5ActivityInfoList_;
    }
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    @java.lang.Override
    public java.util.List<? extends emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder> 
        getH5ActivityInfoListOrBuilderList() {
      return h5ActivityInfoList_;
    }
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    @java.lang.Override
    public int getH5ActivityInfoListCount() {
      return h5ActivityInfoList_.size();
    }
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo getH5ActivityInfoList(int index) {
      return h5ActivityInfoList_.get(index);
    }
    /**
     * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder getH5ActivityInfoListOrBuilder(
        int index) {
      return h5ActivityInfoList_.get(index);
    }

    public static final int RETCODE_FIELD_NUMBER = 14;
    private int retcode_;
    /**
     * <code>int32 retcode = 14;</code>
     * @return The retcode.
     */
    @java.lang.Override
    public int getRetcode() {
      return retcode_;
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
      if (clientRedDotTimestamp_ != 0) {
        output.writeUInt32(3, clientRedDotTimestamp_);
      }
      for (int i = 0; i < h5ActivityInfoList_.size(); i++) {
        output.writeMessage(5, h5ActivityInfoList_.get(i));
      }
      if (retcode_ != 0) {
        output.writeInt32(14, retcode_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (clientRedDotTimestamp_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(3, clientRedDotTimestamp_);
      }
      for (int i = 0; i < h5ActivityInfoList_.size(); i++) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(5, h5ActivityInfoList_.get(i));
      }
      if (retcode_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeInt32Size(14, retcode_);
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
      if (!(obj instanceof emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp other = (emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp) obj;

      if (getClientRedDotTimestamp()
          != other.getClientRedDotTimestamp()) return false;
      if (!getH5ActivityInfoListList()
          .equals(other.getH5ActivityInfoListList())) return false;
      if (getRetcode()
          != other.getRetcode()) return false;
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
      hash = (37 * hash) + CLIENT_RED_DOT_TIMESTAMP_FIELD_NUMBER;
      hash = (53 * hash) + getClientRedDotTimestamp();
      if (getH5ActivityInfoListCount() > 0) {
        hash = (37 * hash) + H5_ACTIVITY_INFO_LIST_FIELD_NUMBER;
        hash = (53 * hash) + getH5ActivityInfoListList().hashCode();
      }
      hash = (37 * hash) + RETCODE_FIELD_NUMBER;
      hash = (53 * hash) + getRetcode();
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parseFrom(
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
    public static Builder newBuilder(emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp prototype) {
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
     *   CMD_ID = 5692;
     *   ENET_CHANNEL_ID = 0;
     *   ENET_IS_RELIABLE = 1;
     * }
     * </pre>
     *
     * Protobuf type {@code GetAllH5ActivityInfoRsp}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:GetAllH5ActivityInfoRsp)
        emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRspOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.internal_static_GetAllH5ActivityInfoRsp_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.internal_static_GetAllH5ActivityInfoRsp_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp.class, emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp.newBuilder()
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
          getH5ActivityInfoListFieldBuilder();
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        clientRedDotTimestamp_ = 0;

        if (h5ActivityInfoListBuilder_ == null) {
          h5ActivityInfoList_ = java.util.Collections.emptyList();
          bitField0_ = (bitField0_ & ~0x00000001);
        } else {
          h5ActivityInfoListBuilder_.clear();
        }
        retcode_ = 0;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.internal_static_GetAllH5ActivityInfoRsp_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp build() {
        emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp buildPartial() {
        emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp result = new emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp(this);
        int from_bitField0_ = bitField0_;
        result.clientRedDotTimestamp_ = clientRedDotTimestamp_;
        if (h5ActivityInfoListBuilder_ == null) {
          if (((bitField0_ & 0x00000001) != 0)) {
            h5ActivityInfoList_ = java.util.Collections.unmodifiableList(h5ActivityInfoList_);
            bitField0_ = (bitField0_ & ~0x00000001);
          }
          result.h5ActivityInfoList_ = h5ActivityInfoList_;
        } else {
          result.h5ActivityInfoList_ = h5ActivityInfoListBuilder_.build();
        }
        result.retcode_ = retcode_;
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
        if (other instanceof emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp) {
          return mergeFrom((emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp other) {
        if (other == emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp.getDefaultInstance()) return this;
        if (other.getClientRedDotTimestamp() != 0) {
          setClientRedDotTimestamp(other.getClientRedDotTimestamp());
        }
        if (h5ActivityInfoListBuilder_ == null) {
          if (!other.h5ActivityInfoList_.isEmpty()) {
            if (h5ActivityInfoList_.isEmpty()) {
              h5ActivityInfoList_ = other.h5ActivityInfoList_;
              bitField0_ = (bitField0_ & ~0x00000001);
            } else {
              ensureH5ActivityInfoListIsMutable();
              h5ActivityInfoList_.addAll(other.h5ActivityInfoList_);
            }
            onChanged();
          }
        } else {
          if (!other.h5ActivityInfoList_.isEmpty()) {
            if (h5ActivityInfoListBuilder_.isEmpty()) {
              h5ActivityInfoListBuilder_.dispose();
              h5ActivityInfoListBuilder_ = null;
              h5ActivityInfoList_ = other.h5ActivityInfoList_;
              bitField0_ = (bitField0_ & ~0x00000001);
              h5ActivityInfoListBuilder_ = 
                com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                   getH5ActivityInfoListFieldBuilder() : null;
            } else {
              h5ActivityInfoListBuilder_.addAllMessages(other.h5ActivityInfoList_);
            }
          }
        }
        if (other.getRetcode() != 0) {
          setRetcode(other.getRetcode());
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
        emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }
      private int bitField0_;

      private int clientRedDotTimestamp_ ;
      /**
       * <code>uint32 client_red_dot_timestamp = 3;</code>
       * @return The clientRedDotTimestamp.
       */
      @java.lang.Override
      public int getClientRedDotTimestamp() {
        return clientRedDotTimestamp_;
      }
      /**
       * <code>uint32 client_red_dot_timestamp = 3;</code>
       * @param value The clientRedDotTimestamp to set.
       * @return This builder for chaining.
       */
      public Builder setClientRedDotTimestamp(int value) {
        
        clientRedDotTimestamp_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 client_red_dot_timestamp = 3;</code>
       * @return This builder for chaining.
       */
      public Builder clearClientRedDotTimestamp() {
        
        clientRedDotTimestamp_ = 0;
        onChanged();
        return this;
      }

      private java.util.List<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo> h5ActivityInfoList_ =
        java.util.Collections.emptyList();
      private void ensureH5ActivityInfoListIsMutable() {
        if (!((bitField0_ & 0x00000001) != 0)) {
          h5ActivityInfoList_ = new java.util.ArrayList<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo>(h5ActivityInfoList_);
          bitField0_ |= 0x00000001;
         }
      }

      private com.google.protobuf.RepeatedFieldBuilderV3<
          emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder> h5ActivityInfoListBuilder_;

      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public java.util.List<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo> getH5ActivityInfoListList() {
        if (h5ActivityInfoListBuilder_ == null) {
          return java.util.Collections.unmodifiableList(h5ActivityInfoList_);
        } else {
          return h5ActivityInfoListBuilder_.getMessageList();
        }
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public int getH5ActivityInfoListCount() {
        if (h5ActivityInfoListBuilder_ == null) {
          return h5ActivityInfoList_.size();
        } else {
          return h5ActivityInfoListBuilder_.getCount();
        }
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo getH5ActivityInfoList(int index) {
        if (h5ActivityInfoListBuilder_ == null) {
          return h5ActivityInfoList_.get(index);
        } else {
          return h5ActivityInfoListBuilder_.getMessage(index);
        }
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder setH5ActivityInfoList(
          int index, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo value) {
        if (h5ActivityInfoListBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureH5ActivityInfoListIsMutable();
          h5ActivityInfoList_.set(index, value);
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.setMessage(index, value);
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder setH5ActivityInfoList(
          int index, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder builderForValue) {
        if (h5ActivityInfoListBuilder_ == null) {
          ensureH5ActivityInfoListIsMutable();
          h5ActivityInfoList_.set(index, builderForValue.build());
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.setMessage(index, builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder addH5ActivityInfoList(emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo value) {
        if (h5ActivityInfoListBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureH5ActivityInfoListIsMutable();
          h5ActivityInfoList_.add(value);
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.addMessage(value);
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder addH5ActivityInfoList(
          int index, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo value) {
        if (h5ActivityInfoListBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureH5ActivityInfoListIsMutable();
          h5ActivityInfoList_.add(index, value);
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.addMessage(index, value);
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder addH5ActivityInfoList(
          emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder builderForValue) {
        if (h5ActivityInfoListBuilder_ == null) {
          ensureH5ActivityInfoListIsMutable();
          h5ActivityInfoList_.add(builderForValue.build());
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.addMessage(builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder addH5ActivityInfoList(
          int index, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder builderForValue) {
        if (h5ActivityInfoListBuilder_ == null) {
          ensureH5ActivityInfoListIsMutable();
          h5ActivityInfoList_.add(index, builderForValue.build());
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.addMessage(index, builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder addAllH5ActivityInfoList(
          java.lang.Iterable<? extends emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo> values) {
        if (h5ActivityInfoListBuilder_ == null) {
          ensureH5ActivityInfoListIsMutable();
          com.google.protobuf.AbstractMessageLite.Builder.addAll(
              values, h5ActivityInfoList_);
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.addAllMessages(values);
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder clearH5ActivityInfoList() {
        if (h5ActivityInfoListBuilder_ == null) {
          h5ActivityInfoList_ = java.util.Collections.emptyList();
          bitField0_ = (bitField0_ & ~0x00000001);
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.clear();
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public Builder removeH5ActivityInfoList(int index) {
        if (h5ActivityInfoListBuilder_ == null) {
          ensureH5ActivityInfoListIsMutable();
          h5ActivityInfoList_.remove(index);
          onChanged();
        } else {
          h5ActivityInfoListBuilder_.remove(index);
        }
        return this;
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder getH5ActivityInfoListBuilder(
          int index) {
        return getH5ActivityInfoListFieldBuilder().getBuilder(index);
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder getH5ActivityInfoListOrBuilder(
          int index) {
        if (h5ActivityInfoListBuilder_ == null) {
          return h5ActivityInfoList_.get(index);  } else {
          return h5ActivityInfoListBuilder_.getMessageOrBuilder(index);
        }
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public java.util.List<? extends emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder> 
           getH5ActivityInfoListOrBuilderList() {
        if (h5ActivityInfoListBuilder_ != null) {
          return h5ActivityInfoListBuilder_.getMessageOrBuilderList();
        } else {
          return java.util.Collections.unmodifiableList(h5ActivityInfoList_);
        }
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder addH5ActivityInfoListBuilder() {
        return getH5ActivityInfoListFieldBuilder().addBuilder(
            emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.getDefaultInstance());
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder addH5ActivityInfoListBuilder(
          int index) {
        return getH5ActivityInfoListFieldBuilder().addBuilder(
            index, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.getDefaultInstance());
      }
      /**
       * <code>repeated .H5ActivityInfo h5_activity_info_list = 5;</code>
       */
      public java.util.List<emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder> 
           getH5ActivityInfoListBuilderList() {
        return getH5ActivityInfoListFieldBuilder().getBuilderList();
      }
      private com.google.protobuf.RepeatedFieldBuilderV3<
          emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder> 
          getH5ActivityInfoListFieldBuilder() {
        if (h5ActivityInfoListBuilder_ == null) {
          h5ActivityInfoListBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
              emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfo.Builder, emu.grasscutter.net.proto.H5ActivityInfoOuterClass.H5ActivityInfoOrBuilder>(
                  h5ActivityInfoList_,
                  ((bitField0_ & 0x00000001) != 0),
                  getParentForChildren(),
                  isClean());
          h5ActivityInfoList_ = null;
        }
        return h5ActivityInfoListBuilder_;
      }

      private int retcode_ ;
      /**
       * <code>int32 retcode = 14;</code>
       * @return The retcode.
       */
      @java.lang.Override
      public int getRetcode() {
        return retcode_;
      }
      /**
       * <code>int32 retcode = 14;</code>
       * @param value The retcode to set.
       * @return This builder for chaining.
       */
      public Builder setRetcode(int value) {
        
        retcode_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>int32 retcode = 14;</code>
       * @return This builder for chaining.
       */
      public Builder clearRetcode() {
        
        retcode_ = 0;
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


      // @@protoc_insertion_point(builder_scope:GetAllH5ActivityInfoRsp)
    }

    // @@protoc_insertion_point(class_scope:GetAllH5ActivityInfoRsp)
    private static final emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp();
    }

    public static emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<GetAllH5ActivityInfoRsp>
        PARSER = new com.google.protobuf.AbstractParser<GetAllH5ActivityInfoRsp>() {
      @java.lang.Override
      public GetAllH5ActivityInfoRsp parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new GetAllH5ActivityInfoRsp(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<GetAllH5ActivityInfoRsp> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<GetAllH5ActivityInfoRsp> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.GetAllH5ActivityInfoRspOuterClass.GetAllH5ActivityInfoRsp getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_GetAllH5ActivityInfoRsp_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_GetAllH5ActivityInfoRsp_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\035GetAllH5ActivityInfoRsp.proto\032\024H5Activ" +
      "ityInfo.proto\"|\n\027GetAllH5ActivityInfoRsp" +
      "\022 \n\030client_red_dot_timestamp\030\003 \001(\r\022.\n\025h5" +
      "_activity_info_list\030\005 \003(\0132\017.H5ActivityIn" +
      "fo\022\017\n\007retcode\030\016 \001(\005B\033\n\031emu.grasscutter.n" +
      "et.protob\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          emu.grasscutter.net.proto.H5ActivityInfoOuterClass.getDescriptor(),
        });
    internal_static_GetAllH5ActivityInfoRsp_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_GetAllH5ActivityInfoRsp_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_GetAllH5ActivityInfoRsp_descriptor,
        new java.lang.String[] { "ClientRedDotTimestamp", "H5ActivityInfoList", "Retcode", });
    emu.grasscutter.net.proto.H5ActivityInfoOuterClass.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}

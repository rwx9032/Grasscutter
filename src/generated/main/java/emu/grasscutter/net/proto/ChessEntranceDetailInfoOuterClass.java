// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: ChessEntranceDetailInfo.proto

package emu.grasscutter.net.proto;

public final class ChessEntranceDetailInfoOuterClass {
  private ChessEntranceDetailInfoOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface ChessEntranceDetailInfoOrBuilder extends
      // @@protoc_insertion_point(interface_extends:ChessEntranceDetailInfo)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    java.util.List<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo> 
        getInfoListList();
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo getInfoList(int index);
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    int getInfoListCount();
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    java.util.List<? extends emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder> 
        getInfoListOrBuilderList();
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder getInfoListOrBuilder(
        int index);
  }
  /**
   * Protobuf type {@code ChessEntranceDetailInfo}
   */
  public static final class ChessEntranceDetailInfo extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:ChessEntranceDetailInfo)
      ChessEntranceDetailInfoOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use ChessEntranceDetailInfo.newBuilder() to construct.
    private ChessEntranceDetailInfo(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private ChessEntranceDetailInfo() {
      infoList_ = java.util.Collections.emptyList();
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new ChessEntranceDetailInfo();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private ChessEntranceDetailInfo(
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
            case 74: {
              if (!((mutable_bitField0_ & 0x00000001) != 0)) {
                infoList_ = new java.util.ArrayList<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo>();
                mutable_bitField0_ |= 0x00000001;
              }
              infoList_.add(
                  input.readMessage(emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.parser(), extensionRegistry));
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
          infoList_ = java.util.Collections.unmodifiableList(infoList_);
        }
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.internal_static_ChessEntranceDetailInfo_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.internal_static_ChessEntranceDetailInfo_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo.class, emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo.Builder.class);
    }

    public static final int INFO_LIST_FIELD_NUMBER = 9;
    private java.util.List<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo> infoList_;
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    @java.lang.Override
    public java.util.List<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo> getInfoListList() {
      return infoList_;
    }
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    @java.lang.Override
    public java.util.List<? extends emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder> 
        getInfoListOrBuilderList() {
      return infoList_;
    }
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    @java.lang.Override
    public int getInfoListCount() {
      return infoList_.size();
    }
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo getInfoList(int index) {
      return infoList_.get(index);
    }
    /**
     * <code>repeated .ChessEntranceInfo info_list = 9;</code>
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder getInfoListOrBuilder(
        int index) {
      return infoList_.get(index);
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
      for (int i = 0; i < infoList_.size(); i++) {
        output.writeMessage(9, infoList_.get(i));
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      for (int i = 0; i < infoList_.size(); i++) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(9, infoList_.get(i));
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
      if (!(obj instanceof emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo other = (emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo) obj;

      if (!getInfoListList()
          .equals(other.getInfoListList())) return false;
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
      if (getInfoListCount() > 0) {
        hash = (37 * hash) + INFO_LIST_FIELD_NUMBER;
        hash = (53 * hash) + getInfoListList().hashCode();
      }
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parseFrom(
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
    public static Builder newBuilder(emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo prototype) {
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
     * Protobuf type {@code ChessEntranceDetailInfo}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:ChessEntranceDetailInfo)
        emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfoOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.internal_static_ChessEntranceDetailInfo_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.internal_static_ChessEntranceDetailInfo_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo.class, emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo.newBuilder()
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
          getInfoListFieldBuilder();
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        if (infoListBuilder_ == null) {
          infoList_ = java.util.Collections.emptyList();
          bitField0_ = (bitField0_ & ~0x00000001);
        } else {
          infoListBuilder_.clear();
        }
        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.internal_static_ChessEntranceDetailInfo_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo build() {
        emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo buildPartial() {
        emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo result = new emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo(this);
        int from_bitField0_ = bitField0_;
        if (infoListBuilder_ == null) {
          if (((bitField0_ & 0x00000001) != 0)) {
            infoList_ = java.util.Collections.unmodifiableList(infoList_);
            bitField0_ = (bitField0_ & ~0x00000001);
          }
          result.infoList_ = infoList_;
        } else {
          result.infoList_ = infoListBuilder_.build();
        }
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
        if (other instanceof emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo) {
          return mergeFrom((emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo other) {
        if (other == emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo.getDefaultInstance()) return this;
        if (infoListBuilder_ == null) {
          if (!other.infoList_.isEmpty()) {
            if (infoList_.isEmpty()) {
              infoList_ = other.infoList_;
              bitField0_ = (bitField0_ & ~0x00000001);
            } else {
              ensureInfoListIsMutable();
              infoList_.addAll(other.infoList_);
            }
            onChanged();
          }
        } else {
          if (!other.infoList_.isEmpty()) {
            if (infoListBuilder_.isEmpty()) {
              infoListBuilder_.dispose();
              infoListBuilder_ = null;
              infoList_ = other.infoList_;
              bitField0_ = (bitField0_ & ~0x00000001);
              infoListBuilder_ = 
                com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                   getInfoListFieldBuilder() : null;
            } else {
              infoListBuilder_.addAllMessages(other.infoList_);
            }
          }
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
        emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }
      private int bitField0_;

      private java.util.List<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo> infoList_ =
        java.util.Collections.emptyList();
      private void ensureInfoListIsMutable() {
        if (!((bitField0_ & 0x00000001) != 0)) {
          infoList_ = new java.util.ArrayList<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo>(infoList_);
          bitField0_ |= 0x00000001;
         }
      }

      private com.google.protobuf.RepeatedFieldBuilderV3<
          emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder> infoListBuilder_;

      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public java.util.List<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo> getInfoListList() {
        if (infoListBuilder_ == null) {
          return java.util.Collections.unmodifiableList(infoList_);
        } else {
          return infoListBuilder_.getMessageList();
        }
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public int getInfoListCount() {
        if (infoListBuilder_ == null) {
          return infoList_.size();
        } else {
          return infoListBuilder_.getCount();
        }
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo getInfoList(int index) {
        if (infoListBuilder_ == null) {
          return infoList_.get(index);
        } else {
          return infoListBuilder_.getMessage(index);
        }
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder setInfoList(
          int index, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo value) {
        if (infoListBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureInfoListIsMutable();
          infoList_.set(index, value);
          onChanged();
        } else {
          infoListBuilder_.setMessage(index, value);
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder setInfoList(
          int index, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder builderForValue) {
        if (infoListBuilder_ == null) {
          ensureInfoListIsMutable();
          infoList_.set(index, builderForValue.build());
          onChanged();
        } else {
          infoListBuilder_.setMessage(index, builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder addInfoList(emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo value) {
        if (infoListBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureInfoListIsMutable();
          infoList_.add(value);
          onChanged();
        } else {
          infoListBuilder_.addMessage(value);
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder addInfoList(
          int index, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo value) {
        if (infoListBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureInfoListIsMutable();
          infoList_.add(index, value);
          onChanged();
        } else {
          infoListBuilder_.addMessage(index, value);
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder addInfoList(
          emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder builderForValue) {
        if (infoListBuilder_ == null) {
          ensureInfoListIsMutable();
          infoList_.add(builderForValue.build());
          onChanged();
        } else {
          infoListBuilder_.addMessage(builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder addInfoList(
          int index, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder builderForValue) {
        if (infoListBuilder_ == null) {
          ensureInfoListIsMutable();
          infoList_.add(index, builderForValue.build());
          onChanged();
        } else {
          infoListBuilder_.addMessage(index, builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder addAllInfoList(
          java.lang.Iterable<? extends emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo> values) {
        if (infoListBuilder_ == null) {
          ensureInfoListIsMutable();
          com.google.protobuf.AbstractMessageLite.Builder.addAll(
              values, infoList_);
          onChanged();
        } else {
          infoListBuilder_.addAllMessages(values);
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder clearInfoList() {
        if (infoListBuilder_ == null) {
          infoList_ = java.util.Collections.emptyList();
          bitField0_ = (bitField0_ & ~0x00000001);
          onChanged();
        } else {
          infoListBuilder_.clear();
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public Builder removeInfoList(int index) {
        if (infoListBuilder_ == null) {
          ensureInfoListIsMutable();
          infoList_.remove(index);
          onChanged();
        } else {
          infoListBuilder_.remove(index);
        }
        return this;
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder getInfoListBuilder(
          int index) {
        return getInfoListFieldBuilder().getBuilder(index);
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder getInfoListOrBuilder(
          int index) {
        if (infoListBuilder_ == null) {
          return infoList_.get(index);  } else {
          return infoListBuilder_.getMessageOrBuilder(index);
        }
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public java.util.List<? extends emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder> 
           getInfoListOrBuilderList() {
        if (infoListBuilder_ != null) {
          return infoListBuilder_.getMessageOrBuilderList();
        } else {
          return java.util.Collections.unmodifiableList(infoList_);
        }
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder addInfoListBuilder() {
        return getInfoListFieldBuilder().addBuilder(
            emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.getDefaultInstance());
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder addInfoListBuilder(
          int index) {
        return getInfoListFieldBuilder().addBuilder(
            index, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.getDefaultInstance());
      }
      /**
       * <code>repeated .ChessEntranceInfo info_list = 9;</code>
       */
      public java.util.List<emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder> 
           getInfoListBuilderList() {
        return getInfoListFieldBuilder().getBuilderList();
      }
      private com.google.protobuf.RepeatedFieldBuilderV3<
          emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder> 
          getInfoListFieldBuilder() {
        if (infoListBuilder_ == null) {
          infoListBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
              emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfo.Builder, emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.ChessEntranceInfoOrBuilder>(
                  infoList_,
                  ((bitField0_ & 0x00000001) != 0),
                  getParentForChildren(),
                  isClean());
          infoList_ = null;
        }
        return infoListBuilder_;
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


      // @@protoc_insertion_point(builder_scope:ChessEntranceDetailInfo)
    }

    // @@protoc_insertion_point(class_scope:ChessEntranceDetailInfo)
    private static final emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo();
    }

    public static emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<ChessEntranceDetailInfo>
        PARSER = new com.google.protobuf.AbstractParser<ChessEntranceDetailInfo>() {
      @java.lang.Override
      public ChessEntranceDetailInfo parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new ChessEntranceDetailInfo(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<ChessEntranceDetailInfo> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<ChessEntranceDetailInfo> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.ChessEntranceDetailInfoOuterClass.ChessEntranceDetailInfo getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_ChessEntranceDetailInfo_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_ChessEntranceDetailInfo_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\035ChessEntranceDetailInfo.proto\032\027ChessEn" +
      "tranceInfo.proto\"@\n\027ChessEntranceDetailI" +
      "nfo\022%\n\tinfo_list\030\t \003(\0132\022.ChessEntranceIn" +
      "foB\033\n\031emu.grasscutter.net.protob\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.getDescriptor(),
        });
    internal_static_ChessEntranceDetailInfo_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_ChessEntranceDetailInfo_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_ChessEntranceDetailInfo_descriptor,
        new java.lang.String[] { "InfoList", });
    emu.grasscutter.net.proto.ChessEntranceInfoOuterClass.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}

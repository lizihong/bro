// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>

#include "Obj.h"
#include "BroList.h"
#include "IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

// Note that there are two kinds of attributes: the kind (here) which
// modify expressions or supply metadata on types, and the kind that
// are extra metadata on every variable instance.

enum [[deprecated("Remove in v4.1. Use zeek::detail::attr_tag instead.")]] attr_tag {
	ATTR_OPTIONAL,
	ATTR_DEFAULT,
	ATTR_REDEF,
	ATTR_ADD_FUNC,
	ATTR_DEL_FUNC,
	ATTR_EXPIRE_FUNC,
	ATTR_EXPIRE_READ,
	ATTR_EXPIRE_WRITE,
	ATTR_EXPIRE_CREATE,
	ATTR_RAW_OUTPUT,
	ATTR_PRIORITY,
	ATTR_GROUP,
	ATTR_LOG,
	ATTR_ERROR_HANDLER,
	ATTR_TYPE_COLUMN,	// for input framework
	ATTR_TRACKED,	// hidden attribute, tracked by NotifierRegistry
	ATTR_ON_CHANGE, // for table change tracking
	ATTR_DEPRECATED,
	NUM_ATTRS // this item should always be last
};

namespace zeek {

class Type;
using TypePtr = IntrusivePtr<Type>;

namespace detail {

using ExprPtr = zeek::IntrusivePtr<zeek::detail::Expr>;

enum attr_tag {
	ATTR_OPTIONAL,
	ATTR_DEFAULT,
	ATTR_REDEF,
	ATTR_ADD_FUNC,
	ATTR_DEL_FUNC,
	ATTR_EXPIRE_FUNC,
	ATTR_EXPIRE_READ,
	ATTR_EXPIRE_WRITE,
	ATTR_EXPIRE_CREATE,
	ATTR_RAW_OUTPUT,
	ATTR_PRIORITY,
	ATTR_GROUP,
	ATTR_LOG,
	ATTR_ERROR_HANDLER,
	ATTR_TYPE_COLUMN,	// for input framework
	ATTR_TRACKED,	// hidden attribute, tracked by NotifierRegistry
	ATTR_ON_CHANGE, // for table change tracking
	ATTR_DEPRECATED,
	NUM_ATTRS // this item should always be last
};

class Attr;
using AttrPtr = zeek::IntrusivePtr<Attr>;
class Attributes;
using AttributesPtr = zeek::IntrusivePtr<Attributes>;

class Attr final : public BroObj {
public:
	static inline const AttrPtr nil;

	Attr(attr_tag t, ExprPtr e);
	explicit Attr(attr_tag t);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	[[deprecated("Remove in v4.1. Use version that takes zeek::detail::attr_tag.")]]
	Attr(::attr_tag t, ExprPtr e);

	[[deprecated("Remove in v4.1. Use version that takes zeek::detail::attr_tag.")]]
	explicit Attr(::attr_tag t);
#pragma GCC diagnostic pop

	~Attr() override;

	attr_tag Tag() const	{ return tag; }

	[[deprecated("Remove in v4.1.  Use GetExpr().")]]
	zeek::detail::Expr* AttrExpr() const	{ return expr.get(); }

	const ExprPtr& GetExpr() const
		{ return expr; }

	void SetAttrExpr(ExprPtr e);

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool shorten = false) const;

	bool operator==(const Attr& other) const
		{
		if ( tag != other.tag )
			return false;

		if ( expr || other.expr )
			// If any has an expression and they aren't the same object, we
			// declare them unequal, as we can't really find out if the two
			// expressions are equivalent.
			return (expr == other.expr);

		return true;
		}

protected:
	void AddTag(ODesc* d) const;

	attr_tag tag;
	ExprPtr expr;
};

// Manages a collection of attributes.
class Attributes final : public BroObj {
public:
	[[deprecated("Remove in v4.1.  Construct using IntrusivePtrs instead.")]]
	Attributes(attr_list* a, zeek::TypePtr t, bool in_record, bool is_global);

	Attributes(std::vector<AttrPtr> a, zeek::TypePtr t,
	           bool in_record, bool is_global);
	Attributes(TypePtr t, bool in_record, bool is_global);

	void AddAttr(AttrPtr a);

	void AddAttrs(const AttributesPtr& a);

	[[deprecated("Remove in v4.1. Pass IntrusivePtr instead.")]]
	void AddAttrs(Attributes* a);	// Unref's 'a' when done

	[[deprecated("Remove in v4.1. Use Find().")]]
	Attr* FindAttr(attr_tag t) const;

	const AttrPtr& Find(attr_tag t) const;

	void RemoveAttr(attr_tag t);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	[[deprecated("Remove in v4.1. Use version that takes zeek::detail::attr_tag.")]]
	Attr* FindAttr(::attr_tag t) const;
	[[deprecated("Remove in v4.1. Use version that takes zeek::detail::attr_tag.")]]
	void RemoveAttr(::attr_tag t);
#pragma GCC diagnostic pop

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool shorten = false) const;

	const std::vector<AttrPtr>& Attrs() const
		{ return attrs; }

	bool operator==(const Attributes& other) const;

protected:
	void CheckAttr(Attr* attr);

	TypePtr type;
	std::vector<AttrPtr> attrs;
	bool in_record;
	bool global_var;
};

} // namespace detail
} // namespace zeek

using Attr [[deprecated("Remove in v4.1. Use zeek::detail::Attr instead.")]] = zeek::detail::Attr;
using Attributes [[deprecated("Remove in v4.1. Use zeek::detail::Attr instead.")]] = zeek::detail::Attributes;

import cpp

/**
 * Returns true if a variable name does NOT match expected
 * Hungarian prefix rules for normal C types.
 */
predicate violatesHungarian(Variable v) {
  exists(Type t |
    t = v.getType()

    // int → n*
    and (
      (t.getUnspecifiedType().getName() = "int" and
       not v.getName().matches("n%"))

    // unsigned int → u*
    or
      (t.getUnspecifiedType().getName() = "unsigned int" and
       not v.getName().matches("u%"))

    // char → c*
    or
      (t.getUnspecifiedType().getName() = "char" and
       not v.getName().matches("c%"))

    // char* → sz*
    // or
    //   (t instanceof PointerType and
    //    (t.getBaseType().getUnspecifiedType().getName() = "char") and
    //    not v.getName().matches("sz%"))

    // any pointer type → p*
    or
      (t instanceof PointerType and
       not v.getName().matches("p%"))

    // float → f*
    or
      (t.getUnspecifiedType().getName() = "float" and
       not v.getName().matches("f%"))

    // double → d*
    or
      (t.getUnspecifiedType().getName() = "double" and
       not v.getName().matches("d%"))

    // struct Something → st*
    // or
    //   (t instanceof RecordType and
    //    not v.getName().matches("st%"))
    )
  )
}

from Variable v
where violatesHungarian(v)
select v, "Variable violates Hungarian naming rules."
